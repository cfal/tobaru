use super::io::{SectionLease, Sections, TimedIo};
use crate::http::message::{invalid, io_error, progress};
use crate::tcp::{setup_http_target_stream, TargetHttpActionData};
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::task::{AbortHandle, JoinSet};

pub(super) struct Client {
    sender: h2::client::SendRequest<Bytes>,
    healthy: Arc<AtomicBool>,
    driver: AbortHandle,
    sections: Sections,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub(crate) struct Clients {
    entries: Mutex<HashMap<usize, ClientSlot>>,
    drivers: Mutex<JoinSet<()>>,
    live: Arc<tokio::sync::Semaphore>,
}

impl Default for Clients {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            drivers: Mutex::new(JoinSet::new()),
            live: Arc::new(tokio::sync::Semaphore::new(16)),
        }
    }
}

type ClientSlot = Arc<tokio::sync::Mutex<Option<Arc<Client>>>>;

pub(super) struct OpenRequest {
    pub response: h2::client::ResponseFuture,
    pub send: h2::SendStream<Bytes>,
    pub _client: Arc<Client>,
    pub _sections: SectionLease,
}

impl Clients {
    pub async fn shutdown(&self) {
        self.entries.lock().clear();
        let mut drivers = std::mem::take(&mut *self.drivers.lock());
        drivers.shutdown().await;
    }

    pub(super) async fn open(
        &self,
        action: &TargetHttpActionData,
        request: http::Request<()>,
        end: bool,
        context: &super::Context,
    ) -> io::Result<OpenRequest> {
        progress(
            context.config.connect_timeout_secs.get(),
            self.open_inner(action, request, end, context),
        )
        .await
    }

    async fn open_inner(
        &self,
        action: &TargetHttpActionData,
        request: http::Request<()>,
        end: bool,
        context: &super::Context,
    ) -> io::Result<OpenRequest> {
        let TargetHttpActionData::Forward {
            id,
            location_data,
            next_address_index,
            ..
        } = action
        else {
            unreachable!()
        };
        let config = context.config;
        let slot = {
            let mut entries = self.entries.lock();
            if !entries.contains_key(id) && entries.len() >= 16 {
                entries.retain(|_, entry| {
                    Arc::strong_count(entry) > 1
                        || match entry.try_lock() {
                            Ok(slot) => slot
                                .as_ref()
                                .is_some_and(|client| Arc::strong_count(client) > 1),
                            Err(_) => true,
                        }
                });
                if entries.len() >= 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Too many active upstream actions",
                    ));
                }
            }
            entries.entry(*id).or_default().clone()
        };
        let client = {
            let mut slot = slot.lock().await;
            if slot
                .as_ref()
                .is_some_and(|client| !client.healthy.load(Ordering::Acquire))
            {
                *slot = None;
            }
            if slot.is_none() {
                let permit = context
                    .physical_backends
                    .clone()
                    .try_acquire_owned()
                    .map_err(io_error)?;
                let frontend_permit = self.live.clone().try_acquire_owned().map_err(io_error)?;
                let index =
                    next_address_index.fetch_add(1, Ordering::Relaxed) % location_data.len();
                let location = &location_data[index];
                let connect = async {
                    let transport = setup_http_target_stream(
                        &context.addr,
                        location,
                        context.nodelay,
                        context.keepalive,
                    )
                    .await?;
                    if location.tls_connector.is_some()
                        && transport.negotiated_alpn.as_deref() != Some(b"h2")
                    {
                        return Err(invalid("Backend did not negotiate h2"));
                    }
                    let io = TimedIo::new(
                        transport.io,
                        vec![],
                        false,
                        Duration::from_secs(config.header_timeout_secs.get()),
                        config.max_header_list_size.get() as usize * 4,
                        config.max_backend_connections.get(),
                    );
                    let watchdog = io.watchdog();
                    let sections = io.sections();
                    let (sender, connection) = h2::client::Builder::new()
                        .enable_push(false)
                        .max_header_list_size(config.max_header_list_size.get())
                        .initial_window_size(65535)
                        .initial_connection_window_size(1024 * 1024)
                        .max_send_buffer_size(16384)
                        .handshake(io)
                        .await
                        .map_err(io_error)?;
                    let healthy = Arc::new(AtomicBool::new(true));
                    let flag = healthy.clone();
                    let mut drivers = self.drivers.lock();
                    while drivers.try_join_next().is_some() {}
                    let driver = drivers.spawn(async move {
                        let _permit = permit;
                        let _frontend_permit = frontend_permit;
                        let result = tokio::select! {
                            result = connection => result.map_err(io_error),
                            error = watchdog => Err(error),
                        };
                        if let Err(error) = result {
                            log::debug!("[h2] backend connection: {error}");
                        }
                        flag.store(false, Ordering::Release);
                    });
                    Ok(Arc::new(Client {
                        sender,
                        healthy,
                        driver,
                        sections,
                    }))
                };
                *slot = Some(progress(config.connect_timeout_secs.get(), connect).await?);
            }
            slot.as_ref().unwrap().clone()
        };
        let mut sender = match progress(config.connect_timeout_secs.get(), async {
            client.sender.clone().ready().await.map_err(io_error)
        })
        .await
        {
            Ok(sender) => sender,
            Err(error) => {
                client.healthy.store(false, Ordering::Release);
                return Err(error);
            }
        };
        // Register before the driver can observe a response on another runtime thread.
        let mut sections = client.sections.lock();
        match sender.send_request(request, end) {
            Ok((response, send)) => {
                sections.insert(send.stream_id().as_u32(), 0);
                let lease = SectionLease::new(client.sections.clone(), send.stream_id().as_u32());
                drop(sections);
                Ok(OpenRequest {
                    response,
                    send,
                    _client: client,
                    _sections: lease,
                })
            }
            Err(error) => {
                client.healthy.store(false, Ordering::Release);
                Err(io_error(error))
            }
        }
    }
}
