use crate::http::message::{
    invalid, io_error, BodyFrame, ReceiveBody, Respond, SendBody, CHUNK_SIZE,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Response};
use parking_lot::Mutex;
use std::future::poll_fn;
use std::io;
use std::sync::Arc;
use std::task::Poll;

pub(super) struct H2Body {
    pub stream: h2::RecvStream,
    data_done: bool,
    finished: bool,
}
impl H2Body {
    pub fn new(stream: h2::RecvStream) -> Self {
        Self {
            stream,
            data_done: false,
            finished: false,
        }
    }
}

#[async_trait]
impl ReceiveBody for H2Body {
    async fn next(&mut self) -> io::Result<Option<BodyFrame>> {
        if self.finished {
            return Ok(None);
        }
        if !self.data_done {
            if let Some(data) = self.stream.data().await {
                return Ok(Some(BodyFrame::Data(data.map_err(io_error)?)));
            }
            self.data_done = true;
        }
        let trailers = self.stream.trailers().await.map_err(io_error)?;
        self.finished = true;
        Ok(trailers.map(BodyFrame::Trailers))
    }
    fn release(&mut self, bytes: usize) -> io::Result<()> {
        self.stream
            .flow_control()
            .release_capacity(bytes)
            .map_err(io_error)
    }
}

pub(super) struct H2Send {
    pub stream: h2::SendStream<Bytes>,
    finished: bool,
}
impl H2Send {
    pub fn new(stream: h2::SendStream<Bytes>, finished: bool) -> Self {
        Self { stream, finished }
    }
}

async fn send_data(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len().min(CHUNK_SIZE));
        let capacity = poll_fn(|cx| {
            if send.capacity() > 0 {
                return Poll::Ready(Ok(send.capacity()));
            }
            match send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(0))) | Poll::Pending => Poll::Pending,
                Poll::Ready(Some(result)) => Poll::Ready(result.map_err(io_error)),
                Poll::Ready(None) => Poll::Ready(Err(invalid("HTTP/2 send stream closed"))),
            }
        })
        .await?;
        let n = capacity.min(data.len()).min(CHUNK_SIZE);
        send.send_data(data.split_to(n), false).map_err(io_error)?;
    }
    send.reserve_capacity(0);
    Ok(())
}

#[async_trait]
impl SendBody for H2Send {
    async fn data(&mut self, data: Bytes) -> io::Result<()> {
        send_data(&mut self.stream, data).await
    }
    async fn trailers(&mut self, trailers: HeaderMap) -> io::Result<()> {
        self.stream.send_trailers(trailers).map_err(io_error)?;
        self.finished = true;
        Ok(())
    }
    async fn finish(&mut self) -> io::Result<()> {
        if !self.finished {
            self.stream
                .send_data(Bytes::new(), true)
                .map_err(io_error)?;
            self.finished = true;
        }
        Ok(())
    }
}

impl Drop for H2Send {
    fn drop(&mut self) {
        if !self.finished {
            self.stream.reserve_capacity(0);
            self.stream.send_reset(h2::Reason::CANCEL);
        }
    }
}

enum ResponseState {
    Head(h2::server::SendResponse<Bytes>),
    Body {
        stream: h2::SendStream<Bytes>,
        finished: bool,
    },
}

#[derive(Clone)]
pub(super) struct H2Response(Arc<Mutex<ResponseState>>);

impl H2Response {
    pub fn new(response: h2::server::SendResponse<Bytes>) -> Self {
        Self(Arc::new(Mutex::new(ResponseState::Head(response))))
    }
    pub fn final_sent(&self) -> bool {
        !matches!(*self.0.lock(), ResponseState::Head(_))
    }
    pub fn reset(&self, reason: h2::Reason) {
        match &mut *self.0.lock() {
            ResponseState::Head(head) => head.send_reset(reason),
            ResponseState::Body { stream, .. } => {
                stream.reserve_capacity(0);
                stream.send_reset(reason);
            }
        }
    }
    pub async fn cancelled(&self) -> io::Result<()> {
        poll_fn(|cx| match &mut *self.0.lock() {
            ResponseState::Head(head) => head.poll_reset(cx),
            ResponseState::Body { stream, .. } => stream.poll_reset(cx),
        })
        .await
        .map_err(io_error)?;
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Frontend reset HTTP/2 stream",
        ))
    }
}

#[async_trait]
impl Respond for H2Response {
    async fn head(&mut self, response: Response<()>, end: bool) -> io::Result<()> {
        let mut state = self.0.lock();
        let ResponseState::Head(head) = &mut *state else {
            return Err(invalid("Response after final head"));
        };
        if response.status().is_informational() {
            return head.send_informational(response).map_err(io_error);
        }
        let body = head.send_response(response, end).map_err(io_error)?;
        *state = ResponseState::Body {
            stream: body,
            finished: end,
        };
        Ok(())
    }
}

#[async_trait]
impl SendBody for H2Response {
    async fn data(&mut self, mut data: Bytes) -> io::Result<()> {
        while !data.is_empty() {
            let requested = data.len().min(CHUNK_SIZE);
            poll_fn(|cx| {
                let mut state = self.0.lock();
                let ResponseState::Body {
                    stream: send,
                    finished: false,
                } = &mut *state
                else {
                    return Poll::Ready(Err(invalid("DATA outside response body")));
                };
                send.reserve_capacity(requested);
                let capacity = if send.capacity() > 0 {
                    send.capacity()
                } else {
                    match send.poll_capacity(cx) {
                        Poll::Pending | Poll::Ready(Some(Ok(0))) => return Poll::Pending,
                        Poll::Ready(Some(Ok(n))) => n,
                        Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io_error(error))),
                        Poll::Ready(None) => {
                            return Poll::Ready(Err(invalid("HTTP/2 stream closed")))
                        }
                    }
                };
                let n = capacity.min(requested);
                let result = send.send_data(data.split_to(n), false).map_err(io_error);
                send.reserve_capacity(0);
                Poll::Ready(result)
            })
            .await?;
        }
        Ok(())
    }
    async fn trailers(&mut self, trailers: HeaderMap) -> io::Result<()> {
        let mut state = self.0.lock();
        let ResponseState::Body {
            stream: send,
            finished,
        } = &mut *state
        else {
            return Err(invalid("Trailers outside body"));
        };
        if *finished {
            return Err(invalid("Trailers after response completion"));
        }
        send.send_trailers(trailers).map_err(io_error)?;
        *finished = true;
        Ok(())
    }
    async fn finish(&mut self) -> io::Result<()> {
        let mut state = self.0.lock();
        if let ResponseState::Body {
            stream: send,
            finished,
        } = &mut *state
        {
            if !*finished {
                send.send_data(Bytes::new(), true).map_err(io_error)?;
                *finished = true;
            }
        }
        Ok(())
    }
}
