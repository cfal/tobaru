use super::*;
use std::io::ErrorKind;
use tokio::time::{sleep, Duration};

fn session<'a>(
    stream: tokio::io::DuplexStream,
    addr: &'a std::net::SocketAddr,
    timeouts: HttpTimeouts,
) -> Session<'a> {
    Session {
        stream: Box::new(stream),
        reader: Some(line_reader::LineReader::new()),
        cached_target: None,
        addr,
        tcp_nodelay: true,
        tcp_keepalive: None,
        timeouts,
    }
}

#[tokio::test(start_paused = true)]
async fn request_header_deadline_does_not_reset_on_partial_progress() {
    let (mut client, stream) = tokio::io::duplex(4096);
    let addr = "127.0.0.1:1".parse().unwrap();
    let mut session = session(
        stream,
        &addr,
        HttpTimeouts {
            request_header_timeout_secs: std::num::NonZeroU64::new(1),
            ..Default::default()
        },
    );
    let (result, ()) = tokio::join!(session.read_request(false), async {
        sleep(Duration::from_millis(600)).await;
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        sleep(Duration::from_millis(600)).await;
    });
    let error = result.err().unwrap();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "HTTP request headers timed out");
}

#[tokio::test(start_paused = true)]
async fn keepalive_idle_and_header_deadlines_are_separate() {
    let (mut client, stream) = tokio::io::duplex(4096);
    let addr = "127.0.0.1:1".parse().unwrap();
    let mut session = session(
        stream,
        &addr,
        HttpTimeouts {
            request_header_timeout_secs: std::num::NonZeroU64::new(1),
            keepalive_idle_timeout_secs: std::num::NonZeroU64::new(5),
            ..Default::default()
        },
    );
    let (result, ()) = tokio::join!(session.read_request(true), async {
        sleep(Duration::from_secs(4)).await;
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        sleep(Duration::from_millis(500)).await;
        client.write_all(b"Host: a.test\r\n\r\n").await.unwrap();
    });
    session.reader = Some(result.unwrap().into_reader());
    let error = session.read_request(true).await.err().unwrap();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "HTTP keepalive idle timed out");
}

#[tokio::test(start_paused = true)]
async fn omitted_timeouts_allow_delayed_headers() {
    let (mut client, stream) = tokio::io::duplex(4096);
    let addr = "127.0.0.1:1".parse().unwrap();
    let mut session = session(stream, &addr, HttpTimeouts::default());
    let (result, ()) = tokio::join!(session.read_request(true), async {
        sleep(Duration::from_secs(3600)).await;
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    });
    assert_eq!(result.unwrap().first_line(), "GET / HTTP/1.1");
}

#[tokio::test(start_paused = true)]
async fn forwarding_times_out_response_headers_but_not_the_body() {
    for send_headers in [false, true] {
        let (mut client, stream) = tokio::io::duplex(4096);
        let (upstream, mut server) = tokio::io::duplex(4096);
        let addr = "127.0.0.1:1".parse().unwrap();
        let action = TargetHttpActionData::try_from(
            serde_json::from_value::<crate::config::HttpPathAction>(serde_json::json!({
                "type":"forward", "location":"127.0.0.1:1"
            }))
            .unwrap(),
        )
        .unwrap();
        let mut session = session(
            stream,
            &addr,
            HttpTimeouts {
                response_header_timeout_secs: std::num::NonZeroU64::new(1),
                ..Default::default()
            },
        );
        session.cached_target = Some(CachedTarget {
            action: &action,
            stream: Box::new(upstream),
            reader: line_reader::LineReader::new(),
        });
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .unwrap();
        let data = session.read_request(false).await.unwrap();
        let paths = Trie::new();
        let request = Request::new(data, "test#1".into(), &paths, &action).unwrap();
        let (result, ()) = tokio::join!(session.forward(request), async {
            let mut bytes = [0; 512];
            assert!(server.read(&mut bytes).await.unwrap() > 0);
            if send_headers {
                server
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            } else {
                server
                    .write_all(b"HTTP/1.1 103 Early Hints\r\n\r\n")
                    .await
                    .unwrap();
            }
            sleep(Duration::from_secs(2)).await;
            if send_headers {
                server.write_all(b"OK").await.unwrap();
            }
        });
        if send_headers {
            assert!(matches!(result.unwrap(), Outcome::Close));
            drop(session);
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.ends_with(b"\r\n\r\nOK"));
        } else {
            let error = result.err().unwrap();
            assert_eq!(error.kind(), ErrorKind::TimedOut);
            assert_eq!(error.to_string(), "HTTP response headers timed out");
        }
    }
}
