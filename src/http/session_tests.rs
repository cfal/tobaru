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

impl Task<std::io::Result<()>> {
    async fn finish(mut self) {
        (&mut self.0).await.unwrap().unwrap();
    }
}

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
        .try_into()
        .unwrap()
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
        let http = crate::tcp::HttpTargetData {
            http_protocols: crate::config::HttpProtocols::default(),
            http2: crate::config::Http2Config::default(),
            h2_admission: crate::http::h2::Admission::new(
                crate::config::Http2Config::default(),
                None,
            ),
            path_configs: paths,
            default_http_action: default,
            http_timeouts: crate::config::HttpTimeouts::default(),
        };
        super::handle_http_stream(
            true,
            None,
            &http,
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

async fn assert_retired(stream: &mut (impl AsyncRead + Unpin)) {
    let mut bytes = Vec::new();
    let result = stream.read_to_end(&mut bytes).await;
    assert!(bytes.is_empty(), "retired backend received another request");
    if let Err(error) = result {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ),
            "{error}"
        );
    }
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
            let (mut client, task) = session(default, Trie::new(), None);
            client
                .write_all(format!("{method} / HTTP/1.1\r\nHost: a.test\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let response = head(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 202 Accepted\r\n"));
            assert_eq!(values(&response, "x-local"), ["yes"]);
            assert!(values(&response, "x-request-id")[0].ends_with("#1"));
            let body = rest(&mut client).await;
            task.finish().await;
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
async fn local_bodyless_statuses_never_send_chunk_framing_or_content() {
    checked(async {
        for status in [204, 205, 304] {
            for method in ["GET", "HEAD"] {
                let default = action(json!({
                    "type":"serve-message", "status_code":status, "content":"must not be sent"
                }));
                let (mut client, task) = session(default, Trie::new(), None);
                client
                    .write_all(format!("{method} / HTTP/1.1\r\nHost: a.test\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                let response = head(&mut client).await;
                assert!(values(&response, "transfer-encoding").is_empty());
                assert_eq!(
                    values(&response, "content-length"),
                    if status == 205 { vec!["0"] } else { vec![] }
                );
                assert!(rest(&mut client).await.is_empty());
                task.finish().await;
            }
        }
    })
    .await;
}

#[tokio::test]
async fn initial_bytes_and_segment_routing_are_preserved() {
    checked(async {
        for (target, expected) in [
            ("/prefix-extra", "default"),
            ("/prefix", "prefix"),
            ("/prefix?x=1", "prefix"),
            ("/prefix/x", "prefix"),
            ("/segment", "segment"),
            ("/segment?x=1", "segment"),
            ("/parent/childishly/x", "parent"),
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
            paths.insert("/parent/childish".into(), vec![route(message("sibling"))]);
            let raw = format!("GET {target} HTTP/1.1\r\nHost: a.test\r\n\r\n");
            let (mut client, task) = session(
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
            task.finish().await;
        }
    })
    .await;
}

#[tokio::test]
async fn duplicate_routing_headers_cannot_fall_through_to_the_default_action() {
    checked(async {
        for fields in [
            "X-Key: wrong\r\nX-Key: secret\r\n",
            "X-Key: secret\r\nx-key: wrong\r\n",
            "X-Key: secret\r\nx-key: secret\r\n",
        ] {
            let mut paths = Trie::new();
            let mut matched = route(message("matched"));
            matched
                .required_request_headers
                .insert("x-key".into(), HttpValueMatch::Single("secret".into()));
            paths.insert("/".into(), vec![matched]);
            let (mut client, mut task) = session(message("default"), paths, None);
            client
                .write_all(format!("GET / HTTP/1.1\r\nHost: a.test\r\n{fields}\r\n").as_bytes())
                .await
                .unwrap();
            assert!(rest(&mut client).await.is_empty());
            let error = (&mut task.0).await.unwrap().unwrap_err();
            assert!(error
                .to_string()
                .contains("Multiple fields for required request header"));
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
        let (mut client, task) = session(message("default"), paths, None);
        client.write_all(b"GET /public/file?x=1 HTTP/1.1\r\nHost: a.test\r\nX-Existing: original\r\nX-Remove: gone\r\n\r\n").await.unwrap();
        let response = head(&mut client).await;
        assert_eq!(values(&response, "location"), ["/public/next"]);
        assert_eq!(values(&response, "x-response"), ["yes"]);
        assert!(rest(&mut client).await.is_empty());
        task.finish().await;
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
        let (mut client, task) = session(forward(address), Trie::new(), None);
        for _ in 0..2 {
            client.write_all(format!("POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            client.write_all(&body).await.unwrap();
            head(&mut client).await;
            let mut received = vec![0; body.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, body);
        }
        assert!(rest(&mut client).await.is_empty());
        task.finish().await;
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
        let (mut client, task) = session(forward(address), Trie::new(), None);
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        for byte in chunks {
            client.write_all(&[*byte]).await.unwrap();
        }
        head(&mut client).await;
        assert_eq!(rest(&mut client).await, chunks);
        task.finish().await;
        (&mut upstream.0).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn directory_get_head_missing_and_query_behavior() {
    checked(async {
        let files = Files::new();
        std::fs::write(files.0.join("index.html"), "index").unwrap();
        for (method, path, status, expected) in [("GET", "/", "200", "5\r\nindex\r\n0\r\n\r\n"), ("HEAD", "/", "200", ""), ("GET", "/index.html?x=1", "200", "5\r\nindex\r\n0\r\n\r\n"), ("POST", "/", "501", "")] {
            let default = action(json!({"type": "serve-directory", "path": files.0, "response_headers": {"x-file": "yes"}}));
            let (mut client, task) = session(default, Trie::new(), None);
            client.write_all(format!("{method} {path} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let response = head(&mut client).await;
            assert!(response.starts_with(&format!("HTTP/1.1 {status}")));
            if status == "200" {
                assert_eq!(values(&response, "x-file"), ["yes"]);
                assert_eq!(values(&response, "content-type"), ["text/html"]);
            }
            assert_eq!(rest(&mut client).await, expected.as_bytes());
            task.finish().await;
        }
    }).await;
}

#[tokio::test]
async fn local_response_refactoring_preserves_empty_and_missing_wire_output() {
    checked(async {
        let (mut client, task) = session(message(""), Trie::new(), None);
        client.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await.unwrap();
        assert_eq!(rest(&mut client).await, b"HTTP/1.1 200\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n0\r\n\r\n");
        task.finish().await;

        let files = Files::new();
        std::fs::create_dir_all(files.0.join("not-file/index.html")).unwrap();
        for path in ["/missing", "/not-file/"] {
            let default = action(json!({"type": "serve-directory", "path": files.0, "response_headers": {"x-file": "yes"}, "response_id_header_name": "x-id"}));
            let (mut client, task) = session(default, Trie::new(), None);
            for (index, connection) in [(1, "keep-alive"), (2, "close")] {
                client.write_all(format!("GET {path} HTTP/1.1\r\nHost: a.test\r\nConnection: {connection}\r\n\r\n").as_bytes()).await.unwrap();
                let response = head(&mut client).await;
                let id = values(&response, "x-id")[0];
                assert!(id.ends_with(&format!("#{index}")));
                assert_eq!(response, format!("HTTP/1.1 404\r\ncontent-length: 0\r\nconnection: {connection}\r\nx-id: {id}\r\n\r\n"));
            }
            assert!(rest(&mut client).await.is_empty());
            task.finish().await;
        }
    }).await;
}

#[tokio::test]
async fn static_paths_decode_filenames_but_reject_parent_segments() {
    checked(async {
        let files = Files::new();
        std::fs::write(files.0.join("report..final name?.txt"), "file").unwrap();
        for target in [
            "/static/report..final%20name%3F.txt?v=1",
            "/static/%2e%2e/private",
            "/static/../private",
            "/static/..%2fprivate",
            "/static/%00",
        ] {
            let paths = Trie::from_iter([(
                "/static/".into(),
                vec![route(action(json!({
                    "type": "serve-directory", "path": files.0,
                })))],
            )]);
            let (mut client, mut task) = session(message("default"), paths, None);
            client
                .write_all(
                    format!("GET {target} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            if target.contains("report") {
                assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
                assert_eq!(rest(&mut client).await, b"4\r\nfile\r\n0\r\n\r\n");
                task.finish().await;
            } else {
                assert!(rest(&mut client).await.is_empty());
                assert_eq!(
                    (&mut task.0).await.unwrap().unwrap_err().to_string(),
                    "Invalid static file path"
                );
            }
        }
    })
    .await;
}

#[tokio::test]
async fn close_action_and_local_expect_rejection() {
    checked(async {
        let (mut client, task) = session(TargetHttpActionData::CloseConnection, Trie::new(), None);
        client.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await.unwrap();
        assert!(rest(&mut client).await.is_empty());
        task.finish().await;
        let (mut client, task) = session(message("hello"), Trie::new(), None);
        client.write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n").await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 417 "));
        assert!(rest(&mut client).await.is_empty());
        task.finish().await;
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
            let (mut client, task) = session(forward(address_b), paths, None);
            for (host, expected) in [("a.test", b'A'), ("b.test", b'B')] {
                client
                    .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                head(&mut client).await;
                assert_eq!(client.read_u8().await.unwrap(), expected);
            }
            assert!(rest(&mut client).await.is_empty());
            task.finish().await;
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
        for (path, expected) in [
            ("/sub/", "Index is outside the serving root"),
            ("/sub/index.html", "File is outside the serving root"),
        ] {
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
            assert_eq!(
                (&mut task.0).await.unwrap().unwrap_err().to_string(),
                format!("Could not canonicalize path: {expected}")
            );
        }
        let default = action(json!({"type": "serve-directory", "path": alias}));
        let (mut client, task) = session(default, Trie::new(), None);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
        assert_eq!(rest(&mut client).await, b"6\r\npublic\r\n0\r\n\r\n");
        task.finish().await;
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
        let (mut client, task) = session(default, Trie::new(), None);
        client.write_all(b"GET / HTTP/1.1\r\nHost: original.test\r\nX-Repeat: first\r\nx-repeat: second\r\nX-Remove: gone\r\n\r\n").await.unwrap();
        let response = head(&mut client).await;
        assert_eq!(values(&response, "set-cookie"), ["a=1", "a=2"]);
        assert!(rest(&mut client).await.is_empty());
        task.finish().await;
        (&mut upstream.0).await.unwrap();
    }).await;
}

#[tokio::test]
async fn pipelining_preserves_surplus_after_every_request_framing() {
    checked(async {
        for (framing, body) in [("", ""), ("Content-Length: 0\r\n", ""), ("Content-Length: 3\r\n", "one"), ("Transfer-Encoding: chunked\r\n", "3\r\none\r\n0\r\nX-End: yes\r\n\r\n")] {
            let (listener, address) = backend().await;
            let mut upstream = Task(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert!(head(&mut stream).await.starts_with("POST /one "));
                let mut received = vec![0; body.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, body.as_bytes());
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA").await.unwrap();
                assert!(head(&mut stream).await.starts_with("GET /two "));
                stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nB\r\n0\r\n\r\n").await.unwrap();
            }));
            let (mut client, task) = session(forward(address), Trie::new(), None);
            client.write_all(format!("POST /one HTTP/1.1\r\nHost: a.test\r\n{framing}\r\n{body}GET /two HTTP/1.1\r\nHost: a.test\r\n\r\n").as_bytes()).await.unwrap();
            head(&mut client).await;
            assert_eq!(client.read_u8().await.unwrap(), b'A');
            head(&mut client).await;
            assert_eq!(rest(&mut client).await, b"1\r\nB\r\n0\r\n\r\n");
            task.finish().await;
            (&mut upstream.0).await.unwrap();
        }
    }).await;
}

#[tokio::test]
async fn static_requests_drain_bodies_without_losing_the_next_request() {
    checked(async {
        let files = Files::new();
        std::fs::write(files.0.join("index.html"), "hello").unwrap();
        let default = action(json!({"type": "serve-directory", "path": files.0}));
        let (mut client, task) = session(default, Trie::new(), None);
        client.write_all(b"HEAD / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 3\r\n\r\nabcGET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n").await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
        assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
        assert_eq!(rest(&mut client).await, b"5\r\nhello\r\n0\r\n\r\n");
        task.finish().await;
    }).await;
}

#[tokio::test]
async fn upgrade_replays_both_sides_read_ahead_and_continues_tunneling() {
    checked(async {
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            head(&mut stream).await;
            stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nSERVER").await.unwrap();
            let mut early = [0; 6];
            stream.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"CLIENT");
            stream.write_all(b"ECHO").await.unwrap();
            assert!(rest(&mut stream).await.is_empty());
        }));
        let (mut client, task) = session(forward(address), Trie::new(), None);
        client.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\nCLIENT").await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 101 "));
        let mut data = [0; 10];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"SERVERECHO");
        client.shutdown().await.unwrap();
        assert!(rest(&mut client).await.is_empty());
        task.finish().await;
        (&mut upstream.0).await.unwrap();
    }).await;
}

#[tokio::test]
async fn head_and_bodyless_statuses_allow_the_following_request() {
    checked(async {
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for response in [
                b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n".as_slice(),
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n",
                b"HTTP/1.1 204 No Content\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
            ] {
                head(&mut stream).await;
                stream.write_all(response).await.unwrap();
            }
        }));
        let (mut client, task) = session(forward(address), Trie::new(), None);
        for (method, status) in [
            ("HEAD", "200"),
            ("GET", "304"),
            ("GET", "204"),
            ("GET", "200"),
        ] {
            client
                .write_all(format!("{method} / HTTP/1.1\r\nHost: a.test\r\n\r\n").as_bytes())
                .await
                .unwrap();
            assert!(head(&mut client)
                .await
                .starts_with(&format!("HTTP/1.1 {status}")));
        }
        assert_eq!(rest(&mut client).await, b"OK");
        task.finish().await;
        (&mut upstream.0).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn expect_and_informational_responses_progress_without_losing_read_ahead() {
    checked(async {
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = head(&mut stream).await;
            assert_eq!(values(&request, "expect"), ["100-Continue"]);
            stream.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </before>\r\n\r\nHTTP/1.1 100 Continue\r\nX-Continue: yes\r\n\r\n").await.unwrap();
            let mut body = [0; 5];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"hello");
            stream.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </after>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await.unwrap();
        }));
        let (mut client, task) = session(forward(address), Trie::new(), None);
        client.write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nExpect: 100-Continue\r\n\r\n").await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 103 "));
        let continuation = head(&mut client).await;
        assert!(continuation.starts_with("HTTP/1.1 100 "));
        assert_eq!(values(&continuation, "x-continue"), ["yes"]);
        client.write_all(b"hello").await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 103 "));
        assert!(head(&mut client).await.starts_with("HTTP/1.1 200 "));
        assert_eq!(rest(&mut client).await, b"OK");
        task.finish().await;
        (&mut upstream.0).await.unwrap();
    }).await;
}

#[tokio::test]
async fn early_final_responses_cancel_incomplete_uploads_and_close() {
    checked(async {
        for expect in ["", "Expect: 100-continue\r\n"] {
            let (listener, address) = backend().await;
            let mut upstream = Task(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                head(&mut stream).await;
                stream
                    .write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 2\r\n\r\nNO")
                    .await
                    .unwrap();
                let _ = rest(&mut stream).await;
            }));
            let (mut client, task) = session(forward(address), Trie::new(), None);
            client
                .write_all(
                    format!(
                        "POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 999999\r\n{expect}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let response = head(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 413 "));
            assert_eq!(values(&response, "connection"), ["close"]);
            assert_eq!(rest(&mut client).await, b"NO");
            task.finish().await;
            (&mut upstream.0).await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn eof_delimited_responses_and_client_close_tokens_end_the_session() {
    checked(async {
        for (response, expected) in [
            (
                b"HTTP/1.1 200 OK\r\n\r\nEOF-BODY".as_slice(),
                b"EOF-BODY".as_slice(),
            ),
            (b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK", b"OK"),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nopaque",
                b"opaque",
            ),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", b"OK"),
        ] {
            let (listener, address) = backend().await;
            let mut upstream = Task(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                head(&mut stream).await;
                stream.write_all(response).await.unwrap();
            }));
            let (mut client, task) = session(forward(address), Trie::new(), None);
            client
                .write_all(
                    b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive, Close\r\n\r\n",
                )
                .await
                .unwrap();
            assert_eq!(values(&head(&mut client).await, "connection"), ["close"]);
            assert_eq!(rest(&mut client).await, expected);
            task.finish().await;
            (&mut upstream.0).await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn ambiguous_request_framing_is_rejected_before_upstream_io() {
    checked(async {
        for (headers, expected) in [
            (
                "Transfer-Encoding: Chunked\r\nContent-Length: 5\r\n",
                "Ambiguous HTTP body framing",
            ),
            (
                "Content-Length: 3\r\nContent-Length: 5\r\n",
                "Conflicting content lengths",
            ),
            (
                "Transfer-Encoding: chunked, gzip\r\n",
                "Chunked must be the final request transfer coding",
            ),
            (
                "Transfer-Encoding: chunked, chunked\r\n",
                "Chunked must be the final request transfer coding",
            ),
            (
                "Transfer-Encoding: gzip\r\n",
                "Chunked must be the final request transfer coding",
            ),
            (
                "Host: conflicting.test\r\n",
                "Multiple Host fields are not allowed",
            ),
        ] {
            let (_listener, address) = backend().await;
            let (mut client, mut task) = session(forward(address), Trie::new(), None);
            client
                .write_all(format!("POST / HTTP/1.1\r\nHost: a.test\r\n{headers}\r\n").as_bytes())
                .await
                .unwrap();
            assert!(rest(&mut client).await.is_empty());
            assert_eq!(
                (&mut task.0).await.unwrap().unwrap_err().to_string(),
                expected
            );
        }
    })
    .await;
}

#[tokio::test]
async fn framing_patches_cannot_change_how_received_bytes_are_consumed() {
    checked(async {
        let (_listener, address) = backend().await;
        let default = action(json!({"type": "forward", "location": address.to_string(), "request_header_patch": {"overwrite_headers": {"Content-Length": "2"}}}));
        let (mut client, mut task) = session(default, Trie::new(), None);
        client.write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 3\r\n\r\nabc").await.unwrap();
        assert!(rest(&mut client).await.is_empty());
        assert_eq!((&mut task.0).await.unwrap().unwrap_err().to_string(), "Request header patch changes body framing");
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            head(&mut stream).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc").await.unwrap();
        }));
        let default = action(json!({"type": "forward", "location": address.to_string(), "response_header_patch": {"remove_headers": ["Content-Length"]}}));
        let (mut client, mut task) = session(default, Trie::new(), None);
        client.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await.unwrap();
        assert!(rest(&mut client).await.is_empty());
        assert_eq!((&mut task.0).await.unwrap().unwrap_err().to_string(), "Response header patch changes body framing");
        (&mut upstream.0).await.unwrap();
    }).await;
}

#[tokio::test]
async fn round_robin_advances_only_when_an_action_opens_a_connection() {
    checked(async {
        let files = Files::new();
        std::fs::write(files.0.join("index.html"), "local").unwrap();
        let (a, address_a) = backend().await;
        let (b, address_b) = backend().await;
        let mut server_a = Task(tokio::spawn(async move {
            let (mut stream, _) = a.accept().await.unwrap();
            for _ in 0..2 {
                head(&mut stream).await;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")
                    .await
                    .unwrap();
            }
            assert!(rest(&mut stream).await.is_empty());
        }));
        let mut server_b = Task(tokio::spawn(async move {
            let (mut stream, _) = b.accept().await.unwrap();
            head(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nB")
                .await
                .unwrap();
        }));
        let mut paths = Trie::new();
        paths.insert(
            "/local/".into(),
            vec![route(action(
                json!({"type": "serve-directory", "path": files.0}),
            ))],
        );
        let default = action(
            json!({"type": "forward", "locations": [address_a.to_string(), address_b.to_string()]}),
        );
        let (mut client, task) = session(default, paths, None);
        for (method, path, body) in [
            ("GET", "/a", Some(b'A')),
            ("GET", "/b", Some(b'A')),
            ("HEAD", "/local/", None),
            ("GET", "/c", Some(b'B')),
        ] {
            client
                .write_all(format!("{method} {path} HTTP/1.1\r\nHost: a.test\r\n\r\n").as_bytes())
                .await
                .unwrap();
            head(&mut client).await;
            if let Some(body) = body {
                assert_eq!(client.read_u8().await.unwrap(), body);
            }
        }
        assert!(rest(&mut client).await.is_empty());
        task.finish().await;
        (&mut server_a.0).await.unwrap();
        (&mut server_b.0).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn surplus_after_a_final_response_is_never_reused() {
    checked(async {
        for (first, body) in [
            ("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA", "A"),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n",
                "1\r\nA\r\n0\r\n\r\n",
            ),
            ("HTTP/1.1 204 No Content\r\n\r\n", ""),
        ] {
            let (listener, address) = backend().await;
            let mut upstream = Task(tokio::spawn(async move {
                let (mut first_stream, _) = listener.accept().await.unwrap();
                head(&mut first_stream).await;
                first_stream
                    .write_all(
                        format!("{first}HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nFAKE")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                assert!(rest(&mut first_stream).await.is_empty());
                let (mut second_stream, _) = listener.accept().await.unwrap();
                head(&mut second_stream).await;
                second_stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nREAL",
                    )
                    .await
                    .unwrap();
            }));
            let (mut client, task) = session(forward(address), Trie::new(), None);
            client
                .write_all(b"GET /first HTTP/1.1\r\nHost: a.test\r\n\r\n")
                .await
                .unwrap();
            head(&mut client).await;
            let mut received = vec![0; body.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, body.as_bytes());
            client
                .write_all(b"GET /second HTTP/1.1\r\nHost: a.test\r\n\r\n")
                .await
                .unwrap();
            head(&mut client).await;
            assert_eq!(rest(&mut client).await, b"REAL");
            task.finish().await;
            (&mut upstream.0).await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn surplus_beyond_the_reader_buffer_is_not_reused() {
    checked(async {
        for total in [32767, 32768, 32769, 65536, 65537] {
            let length = total - b"HTTP/1.1 200 OK\r\nContent-Length: 00000\r\n\r\n".len();
            let (listener, address) = backend().await;
            let mut upstream =
                Task(tokio::spawn(async move {
                    let (mut first, _) = listener.accept().await.unwrap();
                    head(&mut first).await;
                    let mut response =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n").into_bytes();
                    response.extend(vec![b'A'; length]);
                    assert_eq!(response.len(), total);
                    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nFAKE");
                    first.write_all(&response).await.unwrap();
                    assert_retired(&mut first).await;
                    let (mut second, _) = listener.accept().await.unwrap();
                    head(&mut second).await;
                    second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nREAL")
                .await
                .unwrap();
                }));
            let (mut client, task) = session(forward(address), Trie::new(), None);
            client
                .write_all(b"GET /first HTTP/1.1\r\nHost: a.test\r\n\r\n")
                .await
                .unwrap();
            head(&mut client).await;
            let mut body = vec![0; length];
            client.read_exact(&mut body).await.unwrap();
            assert_eq!(body, vec![b'A'; length]);
            client
                .write_all(b"GET /second HTTP/1.1\r\nHost: a.test\r\n\r\n")
                .await
                .unwrap();
            head(&mut client).await;
            let mut second_body = [0; 4];
            client.read_exact(&mut second_body).await.unwrap();
            assert_eq!(&second_body, b"REAL");
            assert!(rest(&mut client).await.is_empty());
            task.finish().await;
            (&mut upstream.0).await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn idle_data_and_closure_retire_tcp_unix_and_tls_backends_before_the_next_head() {
    checked(async {
        use crate::rustls_util::{create_server_config, load_certs, load_private_key};
        use std::sync::Arc;
        let files = Files::new();
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(create_server_config(
            load_certs(identity.cert.pem().as_bytes()).unwrap(),
            &load_private_key(identity.signing_key.serialize_pem().as_bytes()).unwrap(),
            vec![b"http/1.1".to_vec()], &[], &[],
        ).unwrap()));
        for transport in ["tcp", "unix", "tls"] {
            for send_data in [false, true] {
                let (tcp, address) = backend().await;
                let path = files.0.join(format!("{transport}-{send_data}.sock"));
                let unix = tokio::net::UnixListener::bind(&path).unwrap();
                let acceptor = acceptor.clone();
                let (start, started) = tokio::sync::oneshot::channel();
                let (retired, retirement) = tokio::sync::oneshot::channel();
                let mut upstream = Task(tokio::spawn(async move {
                    let connect = || async {
                        let stream: Box<dyn WireStream> = if transport == "unix" {
                            Box::new(unix.accept().await.unwrap().0)
                        } else { Box::new(tcp.accept().await.unwrap().0) };
                        if transport == "tls" {
                            Box::new(acceptor.accept(stream).await.unwrap()) as Box<dyn WireStream>
                        } else { stream }
                    };
                    let mut first = connect().await;
                    assert!(head(&mut first).await.starts_with("GET /first "));
                    first.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA").await.unwrap();
                    first.flush().await.unwrap();
                    started.await.unwrap();
                    if send_data {
                        first.write_all(b"unsolicited").await.unwrap();
                        first.flush().await.unwrap();
                    } else {
                        first.shutdown().await.unwrap();
                    }
                    assert_retired(&mut first).await;
                    retired.send(()).unwrap();
                    let mut second = connect().await;
                    let request = head(&mut second).await;
                    assert!(request.starts_with("POST /second HTTP/1.1\r\n"));
                    assert_eq!(values(&request, "content-length"), ["3"]);
                    let mut body = [0; 3];
                    second.read_exact(&mut body).await.unwrap();
                    assert_eq!(&body, b"abc");
                    second.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nB").await.unwrap();
                    second.shutdown().await.unwrap();
                }));
                let location = match transport {
                    "unix" => json!({"path": path}),
                    "tls" => json!({"address": address.to_string(), "client_tls": {"verify": false, "sni": "localhost"}}),
                    _ => json!({"address": address.to_string()}),
                };
                let (mut client, mut proxy) = session(action(json!({"type": "forward", "location": location})), Trie::new(), None);
                client.write_all(b"GET /first HTTP/1.1\r\nHost: a.test\r\n\r\n").await.unwrap();
                head(&mut client).await;
                assert_eq!(client.read_u8().await.unwrap(), b'A');
                client.write_all(b"POST /second HTTP/1.1\r\nHos").await.unwrap();
                start.send(()).unwrap();
                retirement.await.unwrap();
                client.write_all(b"t: a.test\r\nContent-Length: 3\r\n\r\nabc").await.unwrap();
                head(&mut client).await;
                assert_eq!(rest(&mut client).await, b"B");
                (&mut proxy.0).await.unwrap().unwrap();
                (&mut upstream.0).await.unwrap();
            }
        }
    }).await;
}

#[tokio::test]
async fn early_eof_delimited_rejection_receives_request_eof() {
    checked(async {
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            head(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 413 Content Too Large\r\nConnection: close\r\n\r\nNO")
                .await
                .unwrap();
            let _ = rest(&mut stream).await;
            stream.shutdown().await.unwrap();
        }));
        let (mut client, task) = session(forward(address), Trie::new(), None);
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 99999\r\n\r\nx")
            .await
            .unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 413 "));
        assert_eq!(rest(&mut client).await, b"NO");
        task.finish().await;
        (&mut upstream.0).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn tls_early_rejection_drains_while_upload_shutdown_is_backpressured() {
    checked(async {
        use crate::rustls_util::{create_client_config_with_cert, create_server_config, load_certs, load_private_key};
        use std::sync::Arc;

        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(create_server_config(
            load_certs(identity.cert.pem().as_bytes()).unwrap(),
            &load_private_key(identity.signing_key.serialize_pem().as_bytes()).unwrap(),
            vec![b"http/1.1".to_vec()], &[], &[],
        ).unwrap()));
        let connector = tokio_rustls::TlsConnector::from(create_client_config_with_cert(false, None, vec![b"http/1.1".to_vec()], true, vec![]).unwrap());
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client_tls, server_tls) = tokio::join!(
            connector.connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), client_io),
            acceptor.accept(server_io),
        );
        let (blocked, blockage) = tokio::sync::oneshot::channel();
        let target = super::test_io::ObserveWrite::new(client_tls.unwrap(), blocked);
        let (release, released) = tokio::sync::oneshot::channel();
        let mut upstream = Task(tokio::spawn(async move {
            let mut stream = server_tls.unwrap();
            head(&mut stream).await;
            blockage.await.unwrap();
            stream.write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n").await.unwrap();
            stream.write_all(&vec![b'N'; 1048576]).await.unwrap();
            stream.flush().await.unwrap();
            // Do not drain the upload, even after the complete response has been sent.
            let _ = released.await;
        }));
        let (client, frontend) = UnixStream::pair().unwrap();
        let proxy = Task(tokio::spawn(async move {
            let default = forward("127.0.0.1:1".parse().unwrap());
            let paths = Trie::new();
            let address = "127.0.0.1:12345".parse().unwrap();
            let mut session = super::Session {
                h2: super::h2::Context::testing(),
                tls: false,
                stream: Box::new(frontend), reader: Some(super::line_reader::LineReader::new()),
                cached_target: Some(super::CachedTarget { action: &default, stream: Box::new(target), reader: super::line_reader::LineReader::new() }),
                addr: &address, tcp_nodelay: true, tcp_keepalive: None, timeouts: crate::config::HttpTimeouts::default(),
            };
            let data = session.read_request(false).await?;
            let request = super::Request::new(data, "test#1".into(), &paths, &default)?;
            assert!(matches!(session.dispatch(request).await?, super::Outcome::Close));
            session.stream.shutdown().await
        }));
        let (mut reader, mut writer) = client.into_split();
        let mut upload = Task(tokio::spawn(async move {
            writer.write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 99999999\r\n\r\n").await.unwrap();
            for _ in 0..512 {
                if writer.write_all(&[b'x'; 65536]).await.is_err() {
                    break;
                }
            }
        }));
        assert!(head(&mut reader).await.starts_with("HTTP/1.1 413 "));
        let mut body = vec![0; 1048576];
        reader.read_exact(&mut body).await.unwrap();
        assert_eq!(body, vec![b'N'; 1048576]);
        proxy.finish().await;
        release.send(()).unwrap();
        (&mut upstream.0).await.unwrap();
        (&mut upload.0).await.unwrap();
    }).await;
}

#[tokio::test]
async fn header_patches_cannot_relabel_transfer_codings_or_upgrades() {
    checked(async {
        for (request_headers, request_patch, response, response_patch) in [
            ("Connection: Upgrade\r\nUpgrade: caseproto/V1\r\n", json!({"overwrite_headers": {"Upgrade": "caseproto/v1"}}), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: caseproto/v1\r\n\r\nFRAME", json!({})),
            ("Connection: Upgrade\r\nUpgrade: caseproto/V1\r\n", json!({}), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: caseproto/V1\r\n\r\nFRAME", json!({"overwrite_headers": {"Upgrade": "caseproto/v1"}})),
            ("Connection: Upgrade\r\nUpgrade: caseproto/V1\r\n", json!({}), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: caseproto/v1\r\n\r\nFRAME", json!({})),
            ("Transfer-Encoding: x-dictionary; key=\"A,B\", chunked\r\n", json!({"overwrite_headers": {"Transfer-Encoding": "x-dictionary; key=\"A,b\", chunked"}}), "", json!({})),
            ("", json!({}), "HTTP/1.1 200 OK\r\nTransfer-Encoding: x-dictionary; key=\"A,B\", chunked\r\nConnection: close\r\n\r\n0\r\n\r\n", json!({"overwrite_headers": {"Transfer-Encoding": "x-dictionary; key=\"A,b\", chunked"}})),
            ("Transfer-Encoding: chunked\r\n", json!({"overwrite_headers": {"Transfer-Encoding": "gzip, chunked"}}), "", json!({})),
            ("", json!({}), "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\ncompressed", json!({"remove_headers": ["Transfer-Encoding"]})),
            ("", json!({}), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n", json!({"overwrite_headers": {"Transfer-Encoding": "gzip, chunked"}})),
            ("", json!({"overwrite_headers": {"Connection": "Upgrade", "Upgrade": "websocket"}}), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nFRAME", json!({})),
            ("Connection: Upgrade\r\nUpgrade: websocket\r\n", json!({}), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\nFRAME", json!({"overwrite_headers": {"Upgrade": "websocket"}})),
            ("Connection: Upgrade\r\nUpgrade: websocket\r\n", json!({}), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nFRAME", json!({"overwrite_headers": {"Connection": "Upgrade"}})),
            ("Connection: Upgrade\r\nUpgrade: websocket\r\n", json!({"overwrite_headers": {"Upgrade": "h2c"}}), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\nFRAME", json!({})),
        ] {
            let (listener, address) = backend().await;
            let mut upstream = Task(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                head(&mut stream).await;
                stream.write_all(response.as_bytes()).await.unwrap();
            }));
            let default = action(json!({"type": "forward", "location": address.to_string(), "request_header_patch": request_patch, "response_header_patch": response_patch}));
            let (mut client, mut task) = session(default, Trie::new(), None);
            client.write_all(format!("GET / HTTP/1.1\r\nHost: a.test\r\n{request_headers}\r\n").as_bytes()).await.unwrap();
            assert!(rest(&mut client).await.is_empty());
            let error = (&mut task.0).await.unwrap().unwrap_err();
            if response.is_empty() {
                assert_eq!(error.to_string(), "Request header patch changes body framing");
            } else {
                let expected = if response.starts_with("HTTP/1.1 101 ") { "Invalid upstream protocol upgrade" } else { "Response header patch changes body framing" };
                assert_eq!(error.to_string(), expected);
                (&mut upstream.0).await.unwrap();
            }
        }
    }).await;
}

#[tokio::test]
async fn declined_upgrades_remain_http_and_reuse_the_backend() {
    checked(async {
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(values(&head(&mut stream).await, "upgrade"), ["websocket"]);
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\n\r\nNO").await.unwrap();
            assert!(head(&mut stream).await.starts_with("GET /ordinary "));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await.unwrap();
        }));
        let (mut client, task) = session(forward(address), Trie::new(), None);
        client.write_all(b"GET /upgrade HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 400 "));
        let mut body = [0; 2];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"NO");
        client.write_all(b"GET /ordinary HTTP/1.1\r\nHost: a.test\r\n\r\n").await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 200 "));
        assert_eq!(rest(&mut client).await, b"OK");
        task.finish().await;
        (&mut upstream.0).await.unwrap();
    }).await;
}

#[tokio::test]
async fn frontend_eof_releases_the_cached_backend_without_another_request() {
    checked(async {
        let (listener, address) = backend().await;
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            head(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            assert_retired(&mut stream).await;
        }));
        let (mut client, mut task) = session(forward(address), Trie::new(), None);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .unwrap();
        head(&mut client).await;
        client.shutdown().await.unwrap();
        assert!(rest(&mut client).await.is_empty());
        let error = (&mut task.0).await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        (&mut upstream.0).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn upgraded_streams_progress_bidirectionally_under_backpressure() {
    checked(async {
        let (listener, address) = backend().await;
        let (blocked, blockage) = tokio::sync::oneshot::channel();
        let mut upstream = Task(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            socket2::SockRef::from(&stream).set_send_buffer_size(4096).unwrap();
            head(&mut stream).await;
            let stream = super::test_io::ObserveWrite::new(stream, blocked);
            let (mut reader, mut writer) = tokio::io::split(stream);
            tokio::join!(async {
                let mut response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_vec();
                response.extend(vec![b'S'; 1024 * 1024]);
                writer.write_all(&response).await.unwrap();
                writer.shutdown().await.unwrap();
            }, async {
                assert_eq!(rest(&mut reader).await, vec![b'C'; 1024 * 1024]);
            });
        }));
        let (mut client, task) = session(forward(address), Trie::new(), None);
        client.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
        let (mut reader, mut writer) = client.into_split();
        let mut upload = Task(tokio::spawn(async move {
            writer.write_all(&vec![b'C'; 1024 * 1024]).await.unwrap();
            writer.shutdown().await.unwrap();
        }));
        assert!(head(&mut reader).await.starts_with("HTTP/1.1 101 "));
        blockage.await.unwrap();
        assert_eq!(rest(&mut reader).await, vec![b'S'; 1024 * 1024]);
        task.finish().await;
        (&mut upload.0).await.unwrap();
        (&mut upstream.0).await.unwrap();
    }).await;
}

trait WireStream: AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + tokio::io::AsyncWrite + Unpin + Send> WireStream for T {}

#[tokio::test]
async fn transport_matrix_preserves_tls_pins_mtls_sni_and_alpn() {
    checked(async {
        use crate::async_stream::AsyncStream;
        use crate::rustls_util::{create_client_config_with_cert, create_server_config, load_certs, load_private_key};
        use std::sync::Arc;
        let files = Files::new();
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = identity.cert.pem().into_bytes();
        let key = identity.signing_key.serialize_pem().into_bytes();
        let pin: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, identity.cert.der())
            .as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(files.0.join("cert.pem"), &cert).unwrap();
        std::fs::write(files.0.join("key.pem"), &key).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(create_server_config(
            load_certs(&cert).unwrap(), &load_private_key(&key).unwrap(), vec![b"http/1.1".to_vec()], std::slice::from_ref(&pin), &[],
        ).unwrap()));
        let connector = tokio_rustls::TlsConnector::from(create_client_config_with_cert(
            false, Some((cert, key)), vec![b"http/1.1".to_vec()], true, vec![pin.clone()],
        ).unwrap());
        for frontend_tls in [false, true] {
            for backend_tls in [false, true] {
                for unix in [false, true] {
                    let (tcp, address) = backend().await;
                    let socket_path = files.0.join(format!("backend-{frontend_tls}-{backend_tls}-{unix}.sock"));
                    let unix_listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
                    let acceptor_backend = acceptor.clone();
                    let mut upstream = Task(tokio::spawn(async move {
                        let stream: Box<dyn WireStream> = if unix {
                            Box::new(unix_listener.accept().await.unwrap().0)
                        } else {
                            Box::new(tcp.accept().await.unwrap().0)
                        };
                        let mut stream: Box<dyn WireStream> = if backend_tls {
                            let stream = acceptor_backend.accept(stream).await.unwrap();
                            assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
                            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
                            assert!(stream.get_ref().1.peer_certificates().is_some());
                            Box::new(stream)
                        } else { stream };
                        head(&mut stream).await;
                        let mut body = vec![0; 65536];
                        stream.read_exact(&mut body).await.unwrap();
                        assert!(body.iter().all(|byte| *byte == b'x'));
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\nConnection: close\r\n\r\n").await.unwrap();
                        stream.write_all(&body).await.unwrap();
                        stream.shutdown().await.unwrap();
                    }));
                    let mut location = if unix { json!({"path": socket_path}) } else { json!({"address": address.to_string()}) };
                    if backend_tls {
                        location["client_tls"] = json!({"verify": false, "server_fingerprints": [pin], "sni": "localhost", "alpn": "http/1.1", "cert": files.0.join("cert.pem"), "key": files.0.join("key.pem")});
                    }
                    let default = action(json!({"type": "forward", "location": location}));
                    let (client, server) = UnixStream::pair().unwrap();
                    let acceptor_frontend = acceptor.clone();
                    let mut proxy = Task(tokio::spawn(async move {
                        let stream: Box<dyn AsyncStream> = if frontend_tls {
                            Box::new(acceptor_frontend.accept(server).await.unwrap())
                        } else { Box::new(server) };
                        let http = crate::tcp::HttpTargetData { http_protocols: crate::config::HttpProtocols::default(), h2_admission: crate::http::h2::Admission::new(crate::config::Http2Config::default(), None), http2: crate::config::Http2Config::default(), path_configs: Trie::new(), default_http_action: default, http_timeouts: crate::config::HttpTimeouts::default() };
                        super::handle_http_stream(true, None, &http, stream, &"127.0.0.1:12345".parse().unwrap(), None).await.unwrap();
                    }));
                    let mut client: Box<dyn AsyncStream> = if frontend_tls {
                        Box::new(connector.connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), client).await.unwrap())
                    } else { Box::new(client) };
                    client.write_all(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 65536\r\n\r\n").await.unwrap();
                    client.write_all(&vec![b'x'; 65536]).await.unwrap();
                    client.flush().await.unwrap();
                    assert!(head(&mut client).await.starts_with("HTTP/1.1 200 "));
                    assert_eq!(rest(&mut client).await, vec![b'x'; 65536]);
                    (&mut upstream.0).await.unwrap();
                    (&mut proxy.0).await.unwrap();
                }
            }
        }
    }).await;
}
