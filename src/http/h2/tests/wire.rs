//! Malformed inputs must reach the decoder, not a validating client API.
use super::*;
use futures::FutureExt;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
type Fields = Vec<(Vec<u8>, Vec<u8>)>;

fn field(name: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (name.to_vec(), value.to_vec())
}

fn request(extra: &[(&[u8], &[u8])]) -> Fields {
    let mut fields = vec![
        field(b":method", b"POST"),
        field(b":scheme", b"http"),
        field(b":authority", b"example.test"),
        field(b":path", b"/"),
    ];
    fields.extend(extra.iter().map(|(name, value)| field(name, value)));
    fields
}

// Literal, non-Huffman strings, without indexing (RFC 7541 sections 5.2/6.2.2).
// No encoder-side HTTP validation or dynamic table can hide malformed test input.
fn block(fields: &Fields) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, value: &[u8]) {
        let mut length = value.len();
        if length < 127 {
            out.push(length as u8);
        } else {
            out.push(127);
            length -= 127;
            while length >= 128 {
                out.push((length % 128) as u8 | 128);
                length /= 128;
            }
            out.push(length as u8);
        }
        out.extend_from_slice(value);
    }
    let mut out = Vec::new();
    for (name, value) in fields {
        out.push(0);
        string(&mut out, name);
        string(&mut out, value);
    }
    out
}

struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum Ending {
    EndStream(Vec<u8>),
    Reset(u32),
    ConnectionClosed,
}

struct Peer<T>(T);

impl<T: AsyncRead + tokio::io::AsyncWrite + Unpin> Peer<T> {
    async fn frame(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        assert!(payload.len() <= 16384);
        let mut wire = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        wire.extend_from_slice(&[kind, flags]);
        wire.extend_from_slice(&stream.to_be_bytes());
        wire.extend_from_slice(payload);
        self.0.write_all(&wire).await.unwrap();
    }

    async fn headers(&mut self, stream: u32, fields: &Fields, end: bool) {
        self.sections(stream, &block(fields), end, 16384).await;
    }

    async fn sections(&mut self, stream: u32, bytes: &[u8], end: bool, chunk: usize) {
        assert!(!bytes.is_empty());
        for (index, part) in bytes.chunks(chunk).enumerate() {
            let first = index == 0;
            let last = (index + 1) * chunk >= bytes.len();
            self.frame(
                if first { 1 } else { 9 },
                u8::from(first && end) | if last { 4 } else { 0 },
                stream,
                part,
            )
            .await;
        }
    }

    async fn read(&mut self) -> Option<Frame> {
        loop {
            let mut header = [0; 9];
            if let Err(error) = self.0.read_exact(&mut header).await {
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ));
                return None;
            }
            let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            assert!(length <= 16384);
            let mut payload = vec![0; length];
            self.0.read_exact(&mut payload).await.unwrap();
            let frame = Frame {
                kind: header[3],
                flags: header[4],
                stream: u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff,
                payload,
            };
            match (frame.kind, frame.flags) {
                (4, 0) => self.frame(4, 1, 0, &[]).await,
                (6, 0) => self.frame(6, 1, 0, &frame.payload).await,
                _ => return Some(frame),
            }
        }
    }

    async fn ended(&mut self, stream: u32) -> Ending {
        let mut data = Vec::new();
        while let Some(frame) = self.read().await {
            if frame.kind == 7 {
                return Ending::ConnectionClosed;
            }
            if frame.stream == stream {
                if frame.kind == 0 {
                    data.extend_from_slice(&frame.payload);
                }
                if frame.kind == 3 {
                    return Ending::Reset(u32::from_be_bytes(frame.payload.try_into().unwrap()));
                }
                if matches!(frame.kind, 0 | 1) && frame.flags & 1 != 0 {
                    return Ending::EndStream(data);
                }
            }
        }
        Ending::ConnectionClosed
    }

    async fn completed(&mut self, stream: u32) -> Vec<u8> {
        match self.ended(stream).await {
            Ending::EndStream(data) => data,
            ending => panic!("stream {stream} did not complete successfully: {ending:?}"),
        }
    }
}

#[tokio::test]
async fn wire_harness_distinguishes_success_reset_and_connection_closure() {
    checked(async {
        let (writer, reader) = UnixStream::pair().unwrap();
        let mut writer = Peer(writer);
        let mut reader = Peer(reader);
        writer.frame(0, 0, 1, b"complete-looking payload").await;
        writer.frame(3, 0, 1, &8u32.to_be_bytes()).await;
        assert_eq!(reader.ended(1).await, Ending::Reset(8));
        writer.frame(0, 1, 3, b"complete payload").await;
        assert_eq!(reader.completed(3).await, b"complete payload");
        writer.frame(7, 0, 0, &[0; 8]).await;
        assert_eq!(reader.ended(5).await, Ending::ConnectionClosed);
        drop(writer);
        assert_eq!(reader.ended(7).await, Ending::ConnectionClosed);
    })
    .await;
}

async fn raw_frontend(
    action: TargetHttpActionData,
) -> (Peer<UnixStream>, Task<std::io::Result<()>>) {
    let (client, proxy) = UnixStream::pair().unwrap();
    let target = Arc::new(TargetData {
        tcp_nodelay: true,
        tcp_keepalive: None,
        action_data: TargetActionData::Http(Box::new(runtime(
            action,
            Http2Config::default(),
            None,
        ))),
    });
    let task = Task(tokio::spawn(handle(
        Box::new(proxy),
        "127.0.0.1:1".parse().unwrap(),
        target,
        None,
    )));
    let mut peer = Peer(client);
    peer.0.write_all(PREFACE).await.unwrap();
    peer.frame(4, 0, 0, &[]).await;
    let ack = peer.read().await.unwrap();
    assert_eq!((ack.kind, ack.flags), (4, 1));
    (peer, task)
}

async fn rejects_head(name: &str, fields: Fields, end: bool) {
    checked(async {
        let (listener, addr) = backend().await;
        let (mut peer, _server) = raw_frontend(action(json!({"type":"forward", "location":addr.to_string()}))).await;
        peer.headers(1, &fields, end).await;
        tokio::select! {
            biased;
            accepted = listener.accept() => panic!("{name}: invalid head reached backend: {accepted:?}"),
            _ = peer.ended(1) => {},
        }
        assert!(listener.accept().now_or_never().is_none(), "{name}: backend connection queued");
    }).await;
}

#[tokio::test]
async fn invalid_heads_never_connect_to_h1() {
    let mut cases = Vec::new();
    for name in [
        b"connection".as_slice(),
        b"transfer-encoding",
        b"keep-alive",
        b"proxy-connection",
        b"upgrade",
        b"http2-settings",
    ] {
        cases.push((format!("hop {name:?}"), request(&[(name, b"chunked")])))
    }
    for value in [
        b"chunked".as_slice(),
        b"trailers, chunked",
        b" trailers",
        b"trailers\t",
        b"",
    ] {
        cases.push((format!("te {value:?}"), request(&[(b"te", value)])));
    }
    for values in [
        vec![b"5".as_slice(), b"6"],
        vec![b"6", b"5"],
        vec![b"5, 6"],
        vec![b"5, 5"],
        vec![b""],
        vec![b"+5"],
        vec![b"-1"],
        vec![b" 5"],
        vec![b"5\t"],
        vec![b"18446744073709551616"],
        vec![b"0x5"],
    ] {
        let extra: Vec<_> = values
            .iter()
            .map(|v| (b"content-length".as_slice(), *v))
            .collect();
        cases.push((format!("length {values:?}"), request(&extra)));
    }
    cases.push((
        "cl+te".into(),
        request(&[
            (b"content-length", b"5"),
            (b"transfer-encoding", b"chunked"),
        ]),
    ));
    cases.push((
        "duplicate host".into(),
        request(&[(b"host", b"example.test"), (b"host", b"example.test")]),
    ));
    cases.push((
        "conflicting host".into(),
        request(&[(b"host", b"other.test")]),
    ));
    for name in [
        b"Bad-Case".as_slice(),
        b"bad name",
        b"bad\tname",
        b"bad\r\nname",
        b"bad:name",
        b"",
    ] {
        cases.push((format!("name {name:?}"), request(&[(name, b"value")])));
    }
    for byte in (0..=31u8).filter(|b| *b != b'\t').chain([127]) {
        cases.push((
            format!("value control {byte}"),
            request(&[(b"x-value", &[b'a', byte, b'b'])]),
        ));
    }
    for (name, value) in [
        (b":method".as_slice(), b"GE T".as_slice()),
        (b":method", b"GET\r\nX"),
        (b":method", b""),
        (b":path", b"/ HTTP/1.1"),
        (b":path", b"/\r\nX"),
        (b":path", b"*"),
        (b":path", b"http://other.test/"),
        (b":path", b""),
        (b":authority", b"other.test\r\nX: y"),
        (b":authority", b"user@example.test"),
        (b":authority", b"example.test:bad"),
        (b":authority", b"example.test:65536"),
        (b":authority", b""),
        (b":scheme", b"ftp"),
        (b":scheme", b"http\r\nX"),
    ] {
        let mut fields = request(&[]);
        fields.iter_mut().find(|(n, _)| n == name).unwrap().1 = value.to_vec();
        cases.push((format!("pseudo {name:?} {value:?}"), fields));
    }
    for name in [b":method".as_slice(), b":scheme", b":authority", b":path"] {
        let fields = request(&[]);
        let duplicate = fields.iter().find(|(n, _)| n == name).unwrap().clone();
        let mut duplicated = fields.clone();
        duplicated.push(duplicate);
        cases.push((format!("duplicate {name:?}"), duplicated));
        let mut reordered = fields;
        reordered.insert(0, field(b"x-before-pseudo", b"value"));
        cases.push((format!("reordered {name:?}"), reordered));
    }
    cases.push((
        "PRI *".into(),
        vec![
            field(b":method", b"PRI"),
            field(b":scheme", b"http"),
            field(b":authority", b"example.test"),
            field(b":path", b"*"),
        ],
    ));
    cases.push((
        "oversize head".into(),
        request(&[(b"x-large", &vec![b'a'; 66000])]),
    ));
    let mut many = request(&[]);
    many.extend((0..129).map(|_| field(b"x-repeat", b"v")));
    cases.push(("too many fields".into(), many));
    for (name, fields) in cases {
        rejects_head(&name, fields, false).await;
    }
    rejects_head(
        "nonzero length with END_STREAM",
        request(&[(b"content-length", b"1")]),
        true,
    )
    .await;
}

#[tokio::test]
async fn rejected_request_heads_do_not_affect_forwarded_siblings() {
    for fields in [
        request(&[(b"host", b"other.test")]),
        request(&[(b"content-length", b"5"), (b"content-length", b"6")]),
        request(&[(b"http2-settings", b"invalid")]),
    ] {
        checked(async {
            let (listener, addr) = backend().await;
            let (mut peer, _server) = raw_frontend(action(
                json!({"type":"forward", "location":addr.to_string()}),
            ))
            .await;
            peer.headers(1, &fields, false).await;
            tokio::select! {
                biased;
                _ = listener.accept() => panic!("invalid head reached backend"),
                result = peer.ended(1) => assert_ne!(result, Ending::ConnectionClosed),
            }
            forwarded_sibling(&mut peer, &listener, 3).await;
        })
        .await;
    }
}

fn assert_h1_head(head: &[u8], body: bool) {
    let text = String::from_utf8_lossy(head);
    assert!(text.starts_with("POST / HTTP/1.1\r\n"), "{text}");
    assert_eq!(
        text.matches("\r\nhost: example.test\r\n").count(),
        1,
        "{text}"
    );
    assert_eq!(
        text.matches("\r\nconnection: close\r\n").count(),
        1,
        "{text}"
    );
    assert!(!text.contains("content-length:"), "{text}");
    assert!(!text.contains("\r\nte:"), "{text}");
    assert_eq!(
        text.matches("transfer-encoding: chunked\r\n").count(),
        usize::from(body),
        "{text}"
    );
}

async fn forwarded_sibling(peer: &mut Peer<UnixStream>, listener: &TcpListener, id: u32) {
    peer.headers(id, &request(&[]), true).await;
    let (mut io, _) = listener.accept().await.unwrap();
    assert_h1_head(&head(&mut io).await, false);
    io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        .await
        .unwrap();
    assert_eq!(peer.completed(id).await, b"OK");
    assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn data_cannot_escape_chunks_and_each_exchange_gets_a_new_h1_socket() {
    checked(async {
        let payload = b"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other\r\n\r\n";
        let (listener, addr) = backend().await;
        let (mut peer, _server) = raw_frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        let fields = request(&[
            (b"content-length", payload.len().to_string().as_bytes()),
            (b"content-length", payload.len().to_string().as_bytes()),
            (b"te", b"trailers"),
            (b"cookie", b"a=1"),
            (b"cookie", b"b=2"),
            (b"x-binary", b"a\xffb"),
            (b"x-repeat", b"one"),
            (b"x-repeat", b"two"),
        ]);
        peer.headers(1, &fields, false).await;
        let (mut io, first_address) = listener.accept().await.unwrap();
        let head = head(&mut io).await;
        assert_h1_head(&head, true);
        for bytes in [
            b"cookie: a=1; b=2\r\n".as_slice(),
            b"x-binary: a\xffb\r\n",
            b"x-repeat: one\r\n",
            b"x-repeat: two\r\n",
        ] {
            assert!(head.windows(bytes.len()).any(|part| part == bytes));
        }
        // Padding must neither reach H1 nor count towards Content-Length.
        let mut padded = vec![3];
        padded.extend_from_slice(payload);
        padded.extend_from_slice(&[0; 3]);
        peer.frame(0, 8, 1, &padded).await;
        peer.headers(
            1,
            &vec![field(b"x-proof", b"one"), field(b"x-proof", b"two")],
            true,
        )
        .await;
        let expected = [
            format!("{:x}\r\n", payload.len()).as_bytes(),
            payload,
            b"\r\n0\r\nx-proof: one\r\nx-proof: two\r\n\r\n",
        ]
        .concat();
        let mut captured = vec![0; expected.len()];
        io.read_exact(&mut captured).await.unwrap();
        assert_eq!(captured, expected);
        io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
        assert_eq!(peer.completed(1).await, b"OK");
        assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
        peer.headers(3, &request(&[]), true).await;
        let (mut second, second_address) = listener.accept().await.unwrap();
        assert_ne!(first_address, second_address);
        assert_h1_head(&super::head(&mut second).await, false);
        second
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
        assert_eq!(peer.completed(3).await, b"OK");
    })
    .await;
}

async fn incomplete_upload(
    name: &str,
    fields: Fields,
    data: &[u8],
    end_data: bool,
    trailers: Option<Fields>,
    reset: bool,
) {
    checked(async {
        let (listener, addr) = backend().await;
        let (mut peer, _server) = raw_frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        peer.headers(1, &fields, false).await;
        let (mut io, _) = listener.accept().await.unwrap();
        assert_h1_head(&head(&mut io).await, true);
        peer.frame(0, u8::from(end_data), 1, data).await;
        if let Some(trailers) = trailers {
            peer.headers(1, &trailers, true).await;
        }
        if reset {
            peer.frame(3, 0, 1, &8u32.to_be_bytes()).await;
        }
        let mut wire = Vec::new();
        loop {
            let mut bytes = [0; 4096];
            let n = io.read(&mut bytes).await.unwrap();
            if n == 0 {
                break;
            }
            wire.extend_from_slice(&bytes[..n]);
            assert!(
                !wire.ends_with(b"0\r\n\r\n"),
                "{name}: malformed upload completed: {wire:?}"
            );
        }
        assert!(
            !wire.windows(5).any(|part| part == b"0\r\n\r\n"),
            "{name}: terminal chunk"
        );
        if !reset && peer.ended(1).await == Ending::ConnectionClosed {
            return;
        }
        forwarded_sibling(&mut peer, &listener, 3).await;
    })
    .await;
}

#[tokio::test]
async fn invalid_lengths_and_reset_never_finish_h1_uploads() {
    for (name, length, bytes) in [
        ("short", b"5".as_slice(), b"abc".as_slice()),
        ("long", b"5", b"abcdef"),
        ("zero with data", b"0", b"x"),
    ] {
        incomplete_upload(
            name,
            request(&[(b"content-length", length)]),
            bytes,
            true,
            None,
            false,
        )
        .await;
    }
    incomplete_upload(
        "short at trailers",
        request(&[(b"content-length", b"6")]),
        b"hello",
        false,
        Some(vec![field(b"x-end", b"yes")]),
        false,
    )
    .await;
    incomplete_upload("reset", request(&[]), b"hello", false, None, true).await;
}

#[tokio::test]
async fn forbidden_trailers_never_finish_h1_uploads() {
    for name in [
        b"content-length".as_slice(),
        b"host",
        b"transfer-encoding",
        b"connection",
        b"te",
        b"trailer",
        b"authorization",
        b"proxy-authorization",
        b"content-encoding",
        b"content-type",
        b"content-range",
        b"expect",
    ] {
        incomplete_upload(
            &format!("trailer {name:?}"),
            request(&[]),
            b"hello",
            false,
            Some(vec![field(name, b"0")]),
            false,
        )
        .await;
    }
    for byte in [0, b'\r', b'\n', 11, 127] {
        incomplete_upload(
            &format!("trailer control {byte}"),
            request(&[]),
            b"hello",
            false,
            Some(vec![field(b"x-trailer", &[b'a', byte, b'b'])]),
            false,
        )
        .await;
    }
}

#[tokio::test]
async fn pseudo_trailers_are_rejected_before_lossy_conversion() {
    for (name, value) in [
        (b":path".as_slice(), b"/other".as_slice()),
        (b":status", b"200"),
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"other.test"),
        (b":protocol", b"websocket"),
    ] {
        incomplete_upload(
            &format!("pseudo trailer {name:?}"),
            request(&[]),
            b"hello",
            false,
            Some(vec![field(name, value)]),
            false,
        )
        .await;
    }
}

#[tokio::test]
async fn oversized_trailers_are_rejected_not_truncated() {
    incomplete_upload(
        "oversized trailer",
        request(&[]),
        b"hello",
        false,
        Some(vec![field(b"x-large", &vec![b'a'; 66000])]),
        false,
    )
    .await;
}

#[tokio::test]
async fn rejected_trailers_preserve_hpack_state_for_forwarded_siblings() {
    checked(async {
        let (listener, addr) = backend().await;
        let (mut peer, _server) = raw_frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        peer.headers(1, &request(&[]), false).await;
        let (mut first, _) = listener.accept().await.unwrap();
        let _ = head(&mut first).await;
        let mut oversized = block(&vec![field(b"x-large", &vec![b'a'; 66000])]);
        let mut indexed = block(&vec![field(b"x-indexed", b"kept")]);
        indexed[0] = 0x40; // Literal with incremental indexing, after the limit was exceeded.
        oversized.extend(indexed);
        peer.sections(1, &oversized, true, 16384).await;
        let mut remainder = Vec::new();
        first.read_to_end(&mut remainder).await.unwrap();
        assert!(remainder.is_empty());
        loop {
            let frame = peer.read().await.unwrap();
            assert_ne!(frame.kind, 7, "oversize trailer killed connection");
            if frame.kind == 3 && frame.stream == 1 {
                assert_eq!(frame.payload, 1u32.to_be_bytes()); // PROTOCOL_ERROR
                break;
            }
        }
        let mut next = block(&request(&[]));
        next.push(0xbe); // Dynamic table index 62, the first slot after the static table.
        peer.frame(1, 5, 3, &next).await;
        let (mut sibling, _) = listener.accept().await.unwrap();
        let head = head(&mut sibling).await;
        assert!(head.windows(17).any(|part| part == b"x-indexed: kept\r\n"));
        sibling
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
        assert_eq!(peer.completed(3).await, b"OK");
    })
    .await;
}

#[tokio::test]
async fn trailers_without_end_stream_never_complete_h1_framing() {
    checked(async {
        let (listener, addr) = backend().await;
        let (mut peer, _server) = raw_frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        peer.headers(1, &request(&[]), false).await;
        let (mut io, _) = listener.accept().await.unwrap();
        let _ = head(&mut io).await;
        peer.headers(1, &vec![field(b"x-trailer", b"value")], false)
            .await;
        let mut remainder = Vec::new();
        io.read_to_end(&mut remainder).await.unwrap();
        assert!(remainder.is_empty());
        peer.ended(1).await;
    })
    .await;
}

#[tokio::test]
async fn data_after_end_stream_cannot_append_to_an_h1_request() {
    checked(async {
        let (listener, addr) = backend().await;
        let (mut peer, _server) = raw_frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        peer.headers(1, &request(&[]), true).await;
        let (mut io, _) = listener.accept().await.unwrap();
        assert_h1_head(&head(&mut io).await, false);
        peer.frame(
            0,
            1,
            1,
            b"GET /smuggled HTTP/1.1\r\nHost: example.test\r\n\r\n",
        )
        .await;
        let mut remainder = Vec::new();
        io.read_to_end(&mut remainder).await.unwrap();
        assert!(remainder.is_empty());
        if peer.ended(1).await != Ending::ConnectionClosed {
            forwarded_sibling(&mut peer, &listener, 3).await;
        }
    })
    .await;
}

#[tokio::test]
async fn fragmented_hpack_preserves_h1_framing() {
    checked(async {
        let (listener, addr) = backend().await;
        let (mut peer, _server) = raw_frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        let fields = block(&request(&[(b"content-length", b"0")]));
        for split in 0..=fields.len() {
            let stream = split as u32 * 2 + 1;
            peer.frame(1, 0, stream, &fields[..split]).await;
            peer.frame(9, 4, stream, &fields[split..]).await;
            let (mut io, _) = listener.accept().await.unwrap();
            assert_h1_head(&head(&mut io).await, true);
            peer.frame(0, 1, stream, &[]).await;
            let mut terminal = [0; 5];
            io.read_exact(&mut terminal).await.unwrap();
            assert_eq!(&terminal, b"0\r\n\r\n");
            io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            assert_eq!(peer.completed(stream).await, b"OK");
            assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
        }
    })
    .await;
}

async fn rejected_response(response: h2::client::ResponseFuture, name: &str) {
    let response = match response.await {
        Ok(response) => response,
        Err(error) => {
            assert!(error.is_reset(), "{name}: {error}");
            return;
        }
    };
    if response.status() == 502 {
        assert!(collect(response.into_body()).await.0.is_empty(), "{name}");
        return;
    }
    assert_eq!(response.status(), 200, "{name}");
    let mut body = body::H2Body::new(response.into_body());
    loop {
        match body.next().await {
            Ok(Some(BodyFrame::Data(data))) => body.release(data.len()).unwrap(),
            Ok(Some(BodyFrame::Trailers(_))) => {
                panic!("{name}: invalid response trailers accepted")
            }
            Ok(None) => panic!("{name}: invalid response completed successfully"),
            Err(_) => return,
        }
    }
}

#[tokio::test]
async fn malformed_h1_responses_fail_only_their_exchange() {
    let cases: &[(&str, &[u8])] = &[
        ("cl+te", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        ("conflicting cl", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\nhello"),
        ("reversed cl", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello"),
        ("comma cl", b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\nhello"),
        ("signed cl", b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello"),
        ("overflow cl", b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n"),
        ("repeated te", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        ("unsupported te", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"),
        ("bad field name", b"HTTP/1.1 200 OK\r\nx name: value\r\n\r\n"),
        ("obs fold", b"HTTP/1.1 200 OK\r\nx-name: a\r\n b\r\n\r\n"),
        ("bare cr", b"HTTP/1.1 200 OK\r\nx-name: a\rb\r\n\r\n"),
        ("nul", b"HTTP/1.1 200 OK\r\nx-name: a\0b\r\n\r\n"),
        ("101", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"),
        ("truncated length", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi"),
        ("truncated chunk", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhi"),
        ("bad size", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n"),
        ("overflow size", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n"),
        ("missing chunk crlf", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiX\r\n0\r\n\r\n"),
        ("missing terminal chunk", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n"),
        ("forbidden trailer", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nContent-Length: 2\r\n\r\n"),
        ("pseudo trailer", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n:status: 200\r\n\r\n"),
        ("malformed trailer", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nx-end: a\0b\r\n\r\n"),
    ];
    for &(name, wire) in cases {
        checked(async {
            let (listener, addr) = backend().await;
            let (mut client, _driver, _server) = frontend(action(
                json!({"type":"forward", "location":addr.to_string()}),
            ))
            .await;
            let (bad, _) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/bad")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let (mut io, _) = listener.accept().await.unwrap();
            assert!(head(&mut io).await.starts_with(b"GET /bad "));
            // Keep a forwarded sibling active while the malformed response is decoded.
            let (good, _) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/good")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let (mut sibling, _) = listener.accept().await.unwrap();
            assert!(head(&mut sibling).await.starts_with(b"GET /good "));
            io.write_all(wire).await.unwrap();
            io.shutdown().await.unwrap();
            rejected_response(bad, name).await;
            assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0, "{name}");
            sibling
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            assert_eq!(
                collect(good.await.unwrap().into_body()).await.0,
                b"OK",
                "{name}"
            );
        })
        .await;
    }
}

#[tokio::test]
async fn surplus_h1_response_bytes_cannot_become_another_response() {
    checked(async {
        let (listener, addr) = backend().await;
        let (mut client, _driver, _server) = frontend(action(json!({"type":"forward", "location":addr.to_string()}))).await;
        for first in [true, false] {
            let (response, _) = client.send_request(Request::builder().uri("http://example.test/").body(()).unwrap(), true).unwrap();
            let (mut io, _) = listener.accept().await.unwrap();
            let _ = head(&mut io).await;
            let wire = if first {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOKHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nPOISONED".as_slice()
            } else {
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nCLEAN"
            };
            io.write_all(wire).await.unwrap();
            assert_eq!(collect(response.await.unwrap().into_body()).await.0, if first { b"OK".as_slice() } else { b"CLEAN" });
            assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
        }
    }).await;
}

#[tokio::test]
async fn framing_and_hop_patches_cannot_bypass_validation() {
    for (name, value) in [
        ("content-length", "1"),
        ("transfer-encoding", "chunked"),
        ("connection", "x"),
        ("keep-alive", "timeout=5"),
        ("proxy-connection", "keep-alive"),
        ("upgrade", "h2c"),
        ("http2-settings", "x"),
        ("te", "chunked"),
    ] {
        checked(async {
            let (listener, addr) = backend().await;
            let (mut peer, _server) = raw_frontend(action(json!({"type":"forward", "location":addr.to_string(), "request_header_patch":{"overwrite_headers":{name:value}}}))).await;
            peer.headers(1, &request(&[]), true).await;
            tokio::select! {
                biased;
                _ = listener.accept() => panic!("request patch {name} reached backend"),
                _ = peer.ended(1) => {},
            }
            let (mut client, _driver, _server) = frontend(action(json!({"type":"forward", "location":addr.to_string(), "response_header_patch":{"overwrite_headers":{name:value}}}))).await;
            let (response, _) = client.send_request(Request::builder().uri("http://example.test/").body(()).unwrap(), true).unwrap();
            let (mut io, _) = listener.accept().await.unwrap();
            let _ = head(&mut io).await;
            io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            assert_eq!(response.await.unwrap().status(), 502, "response patch {name}");
            assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
        }).await;
    }
}

#[tokio::test]
async fn invalid_upload_after_early_success_half_closes_h1_without_losing_response() {
    for tls in [false, true] {
        checked(async {
            let (listener, addr) = backend().await;
            let location = if tls {
                json!({"address":addr.to_string(), "client_tls":{"verify":false, "sni":"localhost"}})
            } else {
                json!(addr.to_string())
            };
            let (mut peer, _server) = raw_frontend(action(
                json!({"type":"forward", "location":location}),
            ))
            .await;
            peer.headers(1, &request(&[]), false).await;
            let (io, _) = listener.accept().await.unwrap();
            let mut io: Box<dyn crate::async_stream::AsyncStream> = if tls {
                use crate::rustls_util::{create_server_config, load_certs, load_private_key};
                let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let config = create_server_config(
                    load_certs(identity.cert.pem().as_bytes()).unwrap(),
                    &load_private_key(identity.signing_key.serialize_pem().as_bytes()).unwrap(),
                    vec![b"http/1.1".to_vec()], &[], &[],
                ).unwrap();
                Box::new(tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(io).await.unwrap())
            } else {
                Box::new(io)
            };
            let _ = head(&mut io).await;
            io.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            io.flush().await.unwrap();
            loop {
                let frame = peer.read().await.unwrap();
                if frame.stream == 1 && frame.kind == 1 {
                    break;
                }
            }
            peer.frame(0, 0, 1, b"hello").await;
            peer.headers(1, &vec![field(b"host", b"forbidden.test")], true)
                .await;
            let mut upload = Vec::new();
            io.read_to_end(&mut upload).await.unwrap();
            assert!(!upload.ends_with(b"0\r\n\r\n"));
            io.write_all(b"RESPONSE AFTER EOF").await.unwrap();
            io.shutdown().await.unwrap();
            assert_eq!(peer.completed(1).await, b"RESPONSE AFTER EOF");
            if !tls {
                forwarded_sibling(&mut peer, &listener, 3).await;
            }
        })
        .await;
    }
}

#[tokio::test]
async fn early_success_still_allows_duplex_upload_to_h1() {
    checked(async {
        let (listener, addr) = backend().await;
        let (mut client, _driver, _server) = frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        let (response, mut upload) = client
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("http://example.test/")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let (mut io, _) = listener.accept().await.unwrap();
        let _ = head(&mut io).await;
        io.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n")
            .await
            .unwrap();
        let mut response = response.await.unwrap();
        let first = response.body_mut().data().await.unwrap().unwrap();
        assert_eq!(first, b"a".as_slice());
        response
            .body_mut()
            .flow_control()
            .release_capacity(first.len())
            .unwrap();
        upload
            .send_data(Bytes::from_static(b"hello"), true)
            .unwrap();
        let mut body = [0; 15];
        io.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"5\r\nhello\r\n0\r\n\r\n");
        io.write_all(b"1\r\nb\r\n0\r\n\r\n").await.unwrap();
        assert_eq!(collect(response.into_body()).await.0, b"b");
    })
    .await;
}

#[tokio::test]
async fn stalled_early_responses_release_backend_admission() {
    for status in [200, 413] {
        checked(async {
            let (listener, addr) = backend().await;
            let config = Http2Config {
                max_backend_connections: 1.try_into().unwrap(),
                body_progress_timeout_secs: 1.try_into().unwrap(),
                ..Default::default()
            };
            let (mut client, _driver, _server) = configured_frontend(runtime(
                action(json!({"type":"forward", "location":addr.to_string()})),
                config,
                None,
            ))
            .await;
            let (response, _upload) = client
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri("http://example.test/")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let (mut io, _) = listener.accept().await.unwrap();
            let _ = head(&mut io).await;
            io.write_all(
                format!("HTTP/1.1 {status} Early\r\nContent-Length: 2\r\n\r\na").as_bytes(),
            )
            .await
            .unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), status);
            let mut body = body::H2Body::new(response.into_body());
            loop {
                match body.next().await {
                    Ok(Some(BodyFrame::Data(data))) => body.release(data.len()).unwrap(),
                    Err(_) => break,
                    _ => panic!("stalled response completed"),
                }
            }
            assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
            let (next, _) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let (mut io, _) = listener.accept().await.unwrap();
            let _ = head(&mut io).await;
            io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            assert_eq!(collect(next.await.unwrap().into_body()).await.0, b"OK");
        })
        .await;
    }
}

#[tokio::test]
async fn path_fragments_are_rejected_before_uri_normalization() {
    for path in [
        b"/allowed#fragment".as_slice(),
        b"/allowed?x=y#fragment",
        b"/allowed#\r\nGET /smuggled HTTP/1.1",
    ] {
        let mut fields = request(&[]);
        fields[3].1 = path.to_vec();
        rejects_head("path fragment", fields, true).await;
    }
}

#[tokio::test]
async fn malformed_upstream_h2_trailers_are_rejected_and_connection_remains_usable() {
    let mut cases = vec![("oversized", vec![field(b"x-large", &vec![b'a'; 66000])])];
    for (name, value) in [
        (b":status".as_slice(), b"200".as_slice()),
        (b":path", b"/other"),
    ] {
        cases.push(("pseudo", vec![field(name, value)]));
    }
    for (name, trailers) in cases {
        checked(async {
            let (listener, addr) = backend().await;
            let (mut client, _driver, _server) = frontend(action(
                json!({"type":"forward", "upstream_protocol":"http2", "location":addr.to_string()}),
            ))
            .await;
            let (response, _) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let (mut io, _) = listener.accept().await.unwrap();
            let mut preface = [0; 24];
            io.read_exact(&mut preface).await.unwrap();
            assert_eq!(preface, PREFACE);
            let mut backend = Peer(io);
            backend.frame(4, 0, 0, &[]).await;
            let id = loop {
                let frame = backend.read().await.unwrap();
                if frame.kind == 1 {
                    break frame.stream;
                }
            };
            backend
                .headers(id, &vec![field(b":status", b"200")], false)
                .await;
            backend.frame(0, 0, id, b"hello").await;
            backend.headers(id, &trailers, true).await;
            rejected_response(response, name).await;
            assert_eq!(
                backend.ended(id).await,
                Ending::Reset(1),
                "{name}: expected PROTOCOL_ERROR"
            );
            let (sibling, _) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let next = loop {
                let frame = backend.read().await.unwrap();
                if frame.kind == 1 {
                    break frame.stream;
                }
            };
            assert!(next > id);
            backend
                .headers(next, &vec![field(b":status", b"200")], false)
                .await;
            backend.frame(0, 1, next, b"OK").await;
            assert_eq!(collect(sibling.await.unwrap().into_body()).await.0, b"OK");
            assert!(listener.accept().now_or_never().is_none());
        })
        .await;
    }
}
