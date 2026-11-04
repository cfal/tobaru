use std::collections::HashSet;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use super::broker::{Endpoint, Peer, Session};
use super::protocol::{Id, Message, ALPN};
use super::state::Gate;
use super::stream::ServerIo;
use crate::rustls_util::{
    create_client_config_with_cert, create_server_config, load_certs, load_private_key,
};

#[track_caller]
pub fn expect_create_data(messages: &mut mpsc::Receiver<Message>) -> Id {
    let Message::CreateData { channel_id } = messages.try_recv().unwrap() else {
        panic!("expected creation credit")
    };
    channel_id
}

pub fn harness(active: usize) -> (Arc<Peer>, Arc<Session>, mpsc::Receiver<Message>) {
    let config = serde_json::from_value(serde_json::json!({
        "client_fingerprints":["ab".repeat(32)], "services":["web"],
        "max_active_connections":active, "max_pending_opens":active,
    }))
    .unwrap();
    let gate = Arc::new(Gate::default());
    gate.activate();
    let peer = Arc::new(Peer::new(
        gate,
        config,
        Arc::new(Endpoint::new(Arc::default(), Arc::default(), 16)),
        Arc::default(),
        Arc::default(),
        Arc::default(),
    ));
    let (writer, rx) = mpsc::channel(64);
    let session = Arc::new(Session::new(
        Id::new(),
        vec![1],
        HashSet::from(["web".into()]),
        writer,
    ));
    peer.install(session.clone()).unwrap();
    (peer, session, rx)
}

pub struct Tls {
    pub server: Arc<rustls::ServerConfig>,
    pub connector: tokio_rustls::TlsConnector,
    pub fingerprint: Vec<u8>,
}

impl Tls {
    pub fn new() -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let fingerprint =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, identity.cert.der().as_ref())
                .as_ref()
                .to_vec();
        let pin: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
        let cert = identity.cert.pem().into_bytes();
        let key = identity.signing_key.serialize_pem().into_bytes();
        Self {
            server: Arc::new(
                create_server_config(
                    load_certs(&cert).unwrap(),
                    &load_private_key(&key).unwrap(),
                    vec![ALPN.to_vec()],
                    std::slice::from_ref(&pin),
                    &[],
                )
                .unwrap(),
            ),
            connector: create_client_config_with_cert(
                false,
                Some((cert, key)),
                vec![ALPN.to_vec()],
                true,
                vec![pin],
            )
            .unwrap()
            .into(),
            fingerprint,
        }
    }

    pub async fn pair(&self) -> (ServerIo, tokio_rustls::client::TlsStream<TcpStream>) {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ("127.0.0.1", listener.local_addr().unwrap().port());
        let (server, client) = tokio::join!(
            async {
                let (socket, _) = listener.accept().await.unwrap();
                socket.set_nodelay(true).unwrap();
                tokio_rustls::TlsAcceptor::from(self.server.clone())
                    .accept(socket)
                    .await
                    .unwrap()
            },
            async {
                let socket = TcpStream::connect(address).await.unwrap();
                socket.set_nodelay(true).unwrap();
                self.connector
                    .connect("localhost".try_into().unwrap(), socket)
                    .await
                    .unwrap()
            },
        );
        (server, client)
    }
}
