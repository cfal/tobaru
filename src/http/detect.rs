use crate::config::HttpProtocol;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) async fn protocol(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
    initial: &mut Option<Vec<u8>>,
    deadline: Duration,
) -> io::Result<HttpProtocol> {
    tokio::time::timeout(deadline, async {
        let initial = initial.get_or_insert_with(Vec::new);
        loop {
            let prefix = &initial[..initial.len().min(4)];
            if !b"PRI ".starts_with(prefix) {
                return Ok(HttpProtocol::Http1);
            }
            if prefix.len() == 4 {
                // h2 validates the rest of the preface; never retry it as H1.
                return Ok(HttpProtocol::Http2);
            }
            let mut bytes = [0; 4];
            let count = stream.read(&mut bytes[..4 - prefix.len()]).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Incomplete HTTP protocol prefix",
                ));
            }
            initial.extend_from_slice(&bytes[..count]);
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP protocol detection timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn classification_preserves_buffered_and_unread_bytes() {
        for (wire, expected) in [
            (
                &b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"[..],
                HttpProtocol::Http1,
            ),
            (
                &b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbodyGET /next"[..],
                HttpProtocol::Http1,
            ),
            (&b"PUT / HTTP/1.1\r\n\r\n"[..], HttpProtocol::Http1),
            (&b"PATCH / HTTP/1.1\r\n\r\n"[..], HttpProtocol::Http1),
            (&b"PRINT / HTTP/1.1\r\n\r\n"[..], HttpProtocol::Http1),
            (&b"PRI\t/ HTTP/1.1\r\n\r\n"[..], HttpProtocol::Http1),
            (
                &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nsettings"[..],
                HttpProtocol::Http2,
            ),
            (&b"PRI / HTTP/1.1\r\n\r\n"[..], HttpProtocol::Http2),
        ] {
            for buffered in 0..=wire.len() {
                let mut stream = &wire[buffered..];
                let mut initial = (buffered != 0).then(|| wire[..buffered].to_vec());
                assert_eq!(
                    protocol(&mut stream, &mut initial, Duration::from_secs(1))
                        .await
                        .unwrap(),
                    expected
                );
                let mut replay = initial.unwrap();
                stream.read_to_end(&mut replay).await.unwrap();
                assert_eq!(replay, wire);
            }
        }
    }

    #[tokio::test]
    async fn dispatches_at_four_bytes_without_waiting_for_the_rest_of_the_preface() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            let mut initial = None;
            let selected = protocol(&mut server, &mut initial, Duration::from_secs(1)).await;
            (selected.unwrap(), initial.unwrap())
        });
        for byte in b"PRI" {
            client.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
        }
        client.write_all(b" ").await.unwrap();
        assert_eq!(task.await.unwrap(), (HttpProtocol::Http2, b"PRI ".to_vec()));
    }

    #[tokio::test]
    async fn dispatches_h1_on_the_first_mismatching_byte() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(b"G").await.unwrap();
        let mut initial = None;
        assert_eq!(
            protocol(&mut server, &mut initial, Duration::from_secs(1))
                .await
                .unwrap(),
            HttpProtocol::Http1
        );
        assert_eq!(initial.unwrap(), b"G");
    }

    #[tokio::test]
    async fn rejects_eof_before_a_decision() {
        for prefix in [&b""[..], b"P", b"PR", b"PRI"] {
            let mut stream = prefix;
            let error = protocol(&mut stream, &mut None, Duration::from_secs(1))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn prefix_deadline_is_absolute_despite_progress() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let task =
            tokio::spawn(
                async move { protocol(&mut server, &mut None, Duration::from_secs(1)).await },
            );
        for byte in b"PRI" {
            client.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(400)).await;
        }
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test(start_paused = true)]
    async fn silent_connections_have_a_detection_deadline() {
        let (_client, mut server) = tokio::io::duplex(64);
        assert_eq!(
            protocol(&mut server, &mut None, Duration::from_secs(1))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
