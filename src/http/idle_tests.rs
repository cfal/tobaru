use super::test_io::{ReadStep, ScriptedIo};
use super::*;

fn session<'a>(
    action: &'a TargetHttpActionData,
    frontend: ScriptedIo,
    backend: ScriptedIo,
) -> Session<'a> {
    static ADDRESS: std::net::SocketAddr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        12345,
    ));
    Session {
        stream: Box::new(frontend),
        reader: Some(line_reader::LineReader::new()),
        cached_target: Some(CachedTarget {
            action,
            stream: Box::new(backend),
            reader: line_reader::LineReader::new(),
        }),
        addr: &ADDRESS,
        tcp_nodelay: true,
        tcp_keepalive: None,
    }
}

#[tokio::test]
async fn idle_event_wins_when_both_sides_are_ready() {
    let action = TargetHttpActionData::CloseConnection;
    for event in [
        ReadStep::Data(b"unsolicited".to_vec()),
        ReadStep::Eof,
        ReadStep::Error(std::io::ErrorKind::ConnectionReset),
    ] {
        let frontend = ScriptedIo::new([ReadStep::Data(
            b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(),
        )]);
        let mut session = session(&action, frontend, ScriptedIo::new([event]));
        assert_eq!(
            session.read_request().await.unwrap().first_line(),
            "GET / HTTP/1.1"
        );
        assert!(session.cached_target.is_none());
    }
}

#[tokio::test]
async fn a_quiet_backend_survives_frontend_progress() {
    let action = TargetHttpActionData::CloseConnection;
    let frontend = ScriptedIo::new([ReadStep::Data(b"GET / HTTP/1.1\r\n\r\n".to_vec())]);
    let mut session = session(&action, frontend, ScriptedIo::new([ReadStep::Pending]));
    session.read_request().await.unwrap();
    assert!(session.cached_target.is_some());
}

#[tokio::test]
async fn backend_retirement_keeps_a_partially_parsed_frontend_head_and_body() {
    let action = TargetHttpActionData::CloseConnection;
    let frontend = ScriptedIo::new([
        ReadStep::Data(b"POST /second HTTP/1.1\r\nHost: a.".to_vec()),
        ReadStep::Pending,
        ReadStep::Data(b"test\r\nContent-Length: 3\r\n\r\nabcGET /third HTTP/1.1\r\n\r\n".to_vec()),
    ]);
    let backend = ScriptedIo::new([ReadStep::Pending, ReadStep::Data(b"late response".to_vec())]);
    let mut session = session(&action, frontend, backend);
    let data = session.read_request().await.unwrap();
    assert_eq!(data.first_line(), "POST /second HTTP/1.1");
    assert_eq!(
        data.headers().header_values("host").collect::<Vec<_>>(),
        ["a.test"]
    );
    assert_eq!(
        data.into_reader().unparsed_data(),
        b"abcGET /third HTTP/1.1\r\n\r\n"
    );
    assert!(session.cached_target.is_none());
}
