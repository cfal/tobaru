use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};

use super::protocol::{self, Message};
use super::state::{timed_out, unavailable};

pub struct Pumps {
    pub incoming: mpsc::Receiver<Message>,
    pub outgoing: mpsc::Sender<Message>,
    pub tasks: JoinSet<io::Result<()>>,
}

impl Pumps {
    pub fn new<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream: T,
        receive_timeout: Option<Duration>,
    ) -> Self {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (incoming_tx, incoming) = mpsc::channel(64);
        let (outgoing, mut outgoing_rx) = mpsc::channel(64);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                let message = match receive_timeout {
                    Some(duration) => timeout(duration, protocol::read(&mut reader))
                        .await
                        .map_err(|_| timed_out())??,
                    None => protocol::read(&mut reader).await?,
                };
                incoming_tx.try_send(message).map_err(|_| unavailable())?;
            }
        });
        tasks.spawn(async move {
            while let Some(message) = outgoing_rx.recv().await {
                timeout(
                    Duration::from_secs(10),
                    protocol::write(&mut writer, &message),
                )
                .await
                .map_err(|_| timed_out())??;
            }
            Ok(())
        });
        Self {
            incoming,
            outgoing,
            tasks,
        }
    }

    pub fn send(&self, message: Message) -> io::Result<()> {
        self.outgoing.try_send(message).map_err(|_| unavailable())
    }

    pub async fn stop(&mut self) {
        self.incoming.close();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}
