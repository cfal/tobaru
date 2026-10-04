use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use radix_trie::Trie;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::task::JoinHandle;

use crate::config::{HttpPathAction, HttpValueMatch};
use crate::tcp::{TargetHttpActionData, TargetHttpPathData};

struct Task<T>(JoinHandle<T>);

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn checked(test: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(10), test)
        .await
        .expect("HTTP session test timed out");
}

fn action(value: Value) -> TargetHttpActionData {
    serde_json::from_value::<HttpPathAction>(value)
        .unwrap()
        .into()
}

fn message(content: &str) -> TargetHttpActionData {
    action(json!({"type": "serve-message", "status_code": 200, "content": content}))
}

fn forward(address: std::net::SocketAddr) -> TargetHttpActionData {
    action(json!({"type": "forward", "location": address.to_string()}))
}

fn route(action: TargetHttpActionData) -> TargetHttpPathData {
    TargetHttpPathData {
        required_request_headers: HashMap::new(),
        http_action: action,
    }
}

fn session(
    default: TargetHttpActionData,
    paths: Trie<String, Vec<TargetHttpPathData>>,
    initial: Option<Vec<u8>>,
) -> (UnixStream, Task<std::io::Result<()>>) {
    let (client, proxy) = UnixStream::pair().unwrap();
    let task = tokio::spawn(async move {
        super::handle_http_stream(
            true,
            None,
            &paths,
            &default,
            Box::new(proxy),
            &"127.0.0.1:12345".parse().unwrap(),
            initial,
        )
        .await
    });
    (client, Task(task))
}

async fn backend() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
    (listener, address)
}

async fn head(stream: &mut (impl AsyncRead + Unpin)) -> String {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") {
        data.push(stream.read_u8().await.expect("EOF before HTTP head"));
        assert!(data.len() < 65536);
    }
    String::from_utf8(data).unwrap()
}

fn values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .collect()
}

async fn rest(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    data
}

struct Files(PathBuf);

impl Files {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join("tmp")
            .join(format!(
                "tobaru-http-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn local_message_and_head_preserve_headers_and_ids() {
    checked(async {
        for method in ["GET", "HEAD"] {
            let default = action(json!({
                "type": "serve-message", "status_code": 202,
                "status_message": "Accepted", "content": "hello",
                "response_headers": {"x-local": "yes"},
                "response_id_header_name": "x-request-id"
            }));
            let (mut client, _task) = session(default, Trie::new(), None);
            client
                .write_all(format!("{method} / HTTP/1.1\r\nHost: a.test\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let response = head(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 202 Accepted\r\n"));
            assert_eq!(values(&response, "x-local"), ["yes"]);
            assert!(values(&response, "x-request-id")[0].ends_with("#1"));
            let body = rest(&mut client).await;
            assert_eq!(
                body,
                if method == "HEAD" {
                    b"".as_slice()
                } else {
                    b"5\r\nhello\r\n0\r\n\r\n"
                }
            );
        }
    })
    .await;
}

#[tokio::test]
async fn initial_bytes_and_raw_routing_semantics_are_preserved() {
    checked(async {
        for (target, expected) in [
            ("/prefix-extra", "prefix"),
            ("/segment", "segment"),
            ("/segment?x=1", "default"),
            ("/parent/child/x", "default"),
        ] {
            let mut paths = Trie::new();
            paths.insert("/prefix".into(), vec![route(message("prefix"))]);
            paths.insert("/segment/".into(), vec![route(message("segment"))]);
            paths.insert("/parent/".into(), vec![route(message("parent"))]);
            let mut child = route(message("child"));
            child
                .required_request_headers
                .insert("x-key".into(), HttpValueMatch::Single("secret".into()));
            paths.insert("/parent/child/".into(), vec![child]);
            let raw = format!("GET {target} HTTP/1.1\r\nHost: a.test\r\n\r\n");
            let (mut client, _task) = session(
                message("default"),
                paths,
                Some(raw.as_bytes()[..7].to_vec()),
            );
            client.write_all(&raw.as_bytes()[7..]).await.unwrap();
            head(&mut client).await;
            assert_eq!(
                rest(&mut client).await,
                format!("{:X}\r\n{expected}\r\n0\r\n\r\n", expected.len()).as_bytes()
            );
        }
    })
    .await;
}

#[tokio::test]
async fn forward_rewrites_patches_and_correlates_ids() {
    checked(async {
        let (listener, address) = backend().await;
        let upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = head(&mut stream).await;
            assert!(request.starts_with("GET /internal/file?x=1 HTTP/1.1\r\n"));
            assert_eq!(values(&request, "x-existing"), ["overwritten"]);
            assert_eq!(values(&request, "x-default"), ["added"]);
            assert!(values(&request, "x-remove").is_empty());
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /internal/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            request
        }));
        let mut paths = Trie::new();
        paths.insert("/public/".into(), vec![route(action(json!({
            "type": "forward", "location": address.to_string(), "replacement_path": "/internal/",
            "request_id_header_name": "x-request-id", "response_id_header_name": "x-response-id",
            "request_header_patch": {"remove_headers": ["x-remove"], "overwrite_headers": {"x-existing": "overwritten"}, "default_headers": {"x-existing": "ignored", "x-default": "added"}},
            "response_header_patch": {"default_headers": {"x-response": "yes"}}
        })))]);
        let (mut client, _task) = session(message("default"), paths, None);
        client.write_all(b"GET /public/file?x=1 HTTP/1.1\r\nHost: a.test\r\nX-Existing: original\r\nX-Remove: gone\r\n\r\n").await.unwrap();
        let response = head(&mut client).await;
        assert_eq!(values(&response, "location"), ["/public/next"]);
        assert_eq!(values(&response, "x-response"), ["yes"]);
        assert!(rest(&mut client).await.is_empty());
        let mut upstream = upstream;
        let request = (&mut upstream.0).await.unwrap();
        assert_eq!(values(&response, "x-response-id"), values(&request, "x-request-id"));
    }).await;
}

#[tokio::test]
async fn fixed_length_large_body_and_sequential_reuse() {
    checked(async {
        let body = vec![b'x'; 128 * 1024];
        let expected = body.clone();
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for index in 0..2 {
                let request = head(&mut stream).await;
                assert_eq!(values(&request, "content-length"), [expected.len().to_string()]);
                let mut received = vec![0; expected.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, expected);
                let connection = if index == 0 { "keep-alive" } else { "close" };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n", received.len()).as_bytes()).await.unwrap();
                stream.write_all(&received).await.unwrap();
            }
        }));
        let (mut client, _task) = session(forward(address), Trie::new(), None);
        for _ in 0..2 {
            client.write_all(format!("POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            client.write_all(&body).await.unwrap();
            head(&mut client).await;
            let mut received = vec![0; body.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, body);
        }
        assert!(rest(&mut client).await.is_empty());
        (&mut upstream.0).await.unwrap();
    }).await;
}

#[tokio::test]
async fn raw_chunk_extensions_and_trailers_survive_both_directions() {
    checked(async {
        let chunks = b"5;foo=bar\r\nhello\r\n0;end=yes\r\nX-Trailer: one\r\nX-Trailer: two\r\n\r\n";
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            head(&mut stream).await;
            let mut body = vec![0; chunks.len()];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, chunks);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            for byte in chunks {
                stream.write_all(&[*byte]).await.unwrap();
            }
        }));
        let (mut client, _task) = session(forward(address), Trie::new(), None);
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        for byte in chunks {
            client.write_all(&[*byte]).await.unwrap();
        }
        head(&mut client).await;
        assert_eq!(rest(&mut client).await, chunks);
        (&mut upstream.0).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn directory_get_head_missing_and_query_behavior() {
    checked(async {
        let files = Files::new();
        std::fs::write(files.0.join("index.html"), "index").unwrap();
        for (method, path, status, expected) in [("GET", "/", "200", "5\r\nindex\r\n0\r\n\r\n"), ("HEAD", "/", "200", ""), ("GET", "/index.html?x=1", "404", ""), ("POST", "/", "501", "")] {
            let default = action(json!({"type": "serve-directory", "path": files.0, "response_headers": {"x-file": "yes"}}));
            let (mut client, _task) = session(default, Trie::new(), None);
            client.write_all(format!("{method} {path} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let response = head(&mut client).await;
            assert!(response.starts_with(&format!("HTTP/1.1 {status}")));
            if status == "200" {
                assert_eq!(values(&response, "x-file"), ["yes"]);
                assert_eq!(values(&response, "content-type"), ["text/html"]);
            }
            assert_eq!(rest(&mut client).await, expected.as_bytes());
        }
    }).await;
}

#[tokio::test]
async fn close_action_and_local_expect_rejection() {
    checked(async {
        let (mut client, _task) = session(TargetHttpActionData::CloseConnection, Trie::new(), None);
        client.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await.unwrap();
        assert!(rest(&mut client).await.is_empty());
        let (mut client, _task) = session(message("hello"), Trie::new(), None);
        client.write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n").await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 417 "));
        assert!(rest(&mut client).await.is_empty());
    }).await;
}

#[tokio::test]
async fn same_prefix_host_actions_and_default_use_the_selected_backend() {
    checked(async {
        for use_default in [false, true] {
            let (a, address_a) = backend().await;
            let (b, address_b) = backend().await;
            let mut server_a = Task(tokio::spawn(async move {
                let (mut stream, _) = a.accept().await.unwrap();
                let request = head(&mut stream).await;
                assert_eq!(values(&request, "host"), ["a.test"]);
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")
                    .await
                    .unwrap();
                assert!(rest(&mut stream).await.is_empty());
            }));
            let mut server_b = Task(tokio::spawn(async move {
                let (mut stream, _) = b.accept().await.unwrap();
                let request = head(&mut stream).await;
                assert_eq!(values(&request, "host"), ["b.test"]);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nB",
                    )
                    .await
                    .unwrap();
            }));
            let mut paths = Trie::new();
            let mut first = route(forward(address_a));
            first
                .required_request_headers
                .insert("host".into(), HttpValueMatch::Single("a.test".into()));
            let mut alternatives = vec![first];
            if !use_default {
                alternatives.push(route(forward(address_b)));
            }
            paths.insert("/".into(), alternatives);
            let (mut client, _task) = session(forward(address_b), paths, None);
            for (host, expected) in [("a.test", b'A'), ("b.test", b'B')] {
                client
                    .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                head(&mut client).await;
                assert_eq!(client.read_u8().await.unwrap(), expected);
            }
            assert!(rest(&mut client).await.is_empty());
            (&mut server_a.0).await.unwrap();
            (&mut server_b.0).await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn directory_checks_index_symlinks_and_canonicalizes_the_root() {
    checked(async {
        let files = Files::new();
        let root = files.0.join("static");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(files.0.join("outside.txt"), "private").unwrap();
        std::os::unix::fs::symlink(files.0.join("outside.txt"), root.join("sub/index.html"))
            .unwrap();
        std::fs::write(root.join("index.html"), "public").unwrap();
        let alias = files.0.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        for path in ["/sub/", "/sub/index.html"] {
            let default = action(json!({"type": "serve-directory", "path": alias}));
            let (mut client, mut task) = session(default, Trie::new(), None);
            client
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            assert!(rest(&mut client).await.is_empty());
            assert!((&mut task.0).await.unwrap().is_err());
        }
        let default = action(json!({"type": "serve-directory", "path": alias}));
        let (mut client, _task) = session(default, Trie::new(), None);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
        assert_eq!(rest(&mut client).await, b"6\r\npublic\r\n0\r\n\r\n");
    })
    .await;
}

#[tokio::test]
async fn duplicate_fields_and_mixed_case_patches_survive_forwarding() {
    checked(async {
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = head(&mut stream).await;
            assert_eq!(values(&request, "host"), ["replacement.test"]);
            assert_eq!(values(&request, "x-repeat"), ["first", "second"]);
            assert!(values(&request, "x-remove").is_empty());
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\nSet-Cookie: a=1\r\nSet-Cookie: a=2\r\n\r\n").await.unwrap();
        }));
        let default = action(json!({"type": "forward", "location": address.to_string(), "request_header_patch": {"remove_headers": ["X-Remove"], "overwrite_headers": {"Host": "replacement.test"}}}));
        let (mut client, _task) = session(default, Trie::new(), None);
        client.write_all(b"GET / HTTP/1.1\r\nHost: original.test\r\nX-Repeat: first\r\nx-repeat: second\r\nX-Remove: gone\r\n\r\n").await.unwrap();
        let response = head(&mut client).await;
        assert_eq!(values(&response, "set-cookie"), ["a=1", "a=2"]);
        assert!(rest(&mut client).await.is_empty());
        (&mut upstream.0).await.unwrap();
    }).await;
}
