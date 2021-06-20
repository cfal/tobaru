// Forked from tokio's copy.rs and copy_bidirectional.rs.
//
// Changes:
// - Customizable buffer size

use futures_util::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug)]
struct CopyBuffer {
    read_done: bool,
    pos: usize,
    cap: usize,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            read_done: false,
            pos: 0,
            cap: 0,
            buf: vec![0; size].into_boxed_slice(),
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        let mut read_pending = false;
        let mut write_pending = false;
        loop {
            let mut did_action = false;

            // If our buffer has some space, let's read up!
            if !read_pending && !self.read_done && self.cap < self.buf.len() {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf[me.cap..]);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Pending => {
                        read_pending = true;
                    }
                    Poll::Ready(val) => {
                        val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cap += n;
                        }
                    }
                }
                did_action = true;
            }

            // If our buffer has some data, let's write it out!
            if !write_pending && self.pos < self.cap {
                let me = &mut *self;
                match writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]) {
                    Poll::Pending => {
                        write_pending = true;
                    }
                    Poll::Ready(val) => {
                        let i = val?;
                        if i == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into writer",
                            )));
                        } else {
                            self.pos += i;
                            if self.pos == self.cap {
                                self.pos = 0;
                                self.cap = 0;
                            }
                        }
                    }
                };
                did_action = true;
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.read_done && self.cap == 0 {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(()));
            }

            if !did_action {
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running,
    ShuttingDown,
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyBuffer,
    b_buf: CopyBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncRead + Unpin + ?Sized,
    B: AsyncWrite + Unpin + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown;
            }
            TransferState::ShuttingDown => {
                ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_buf,
            b_buf,
            a_to_b,
            b_to_a,
        } = &mut *self;

        let a_to_b = transfer_one_direction(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
        let b_to_a = transfer_one_direction(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);

        if a_to_b.is_ready() {
            a_to_b
        } else {
            b_to_a
        }
    }
}

/// Copies data in both directions between `a` and `b`.
///
/// This function returns a future that will read from both streams,
/// writing any data read to the opposing stream.
/// This happens in both directions concurrently.
///
/// If an EOF is observed on one stream, [`shutdown()`] will be invoked on
/// the other, and reading from that stream will stop. Copying of data in
/// the other direction will continue.
///
/// The future will complete successfully once both directions of communication has been shut down.
/// A direction is shut down when the reader reports EOF,
/// at which point [`shutdown()`] is called on the corresponding writer. When finished,
/// it will return a tuple of the number of bytes copied from a to b
/// and the number of bytes copied from b to a, in that order.
///
/// [`shutdown()`]: crate::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation on `a`
/// or `b` returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
/// # Return value
///
/// Returns a tuple of bytes copied `a` to `b` and bytes copied `b` to `a`.
pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    buffer_size: usize,
) -> Result<(), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_buf: CopyBuffer::new(buffer_size),
        b_buf: CopyBuffer::new(buffer_size),
        a_to_b: TransferState::Running,
        b_to_a: TransferState::Running,
    }
    .await
}
