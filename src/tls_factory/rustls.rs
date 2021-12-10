use crate::async_stream::AsyncStream;
use crate::async_tls::{AsyncTlsAcceptor, AsyncTlsConnector, AsyncTlsFactory};

use std::lazy::SyncOnceCell;
use std::sync::Arc;

use async_trait::async_trait;
use rustls::Session;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[async_trait]
impl AsyncStream for tokio_rustls::client::TlsStream<TcpStream> {
    async fn try_shutdown(&mut self) -> std::io::Result<()> {
        self.shutdown().await
    }
}

#[async_trait]
impl AsyncStream for tokio_rustls::server::TlsStream<TcpStream> {
    async fn try_shutdown(&mut self) -> std::io::Result<()> {
        self.shutdown().await
    }
}

#[async_trait]
impl AsyncTlsAcceptor for tokio_rustls::TlsAcceptor {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Box<dyn AsyncStream>> {
        tokio_rustls::TlsAcceptor::accept(&self, stream)
            .await
            .map(|mut s| {
                s.get_mut().1.set_buffer_limit(8192);
                Box::new(s) as Box<dyn AsyncStream>
            })
    }
}

fn get_dummy_dns_ref() -> webpki::DNSNameRef<'static> {
    static INSTANCE: SyncOnceCell<webpki::DNSNameRef> = SyncOnceCell::new();
    INSTANCE
        .get_or_init(|| webpki::DNSNameRef::try_from_ascii_str("example.com").unwrap())
        .clone()
}

#[async_trait]
impl AsyncTlsConnector for tokio_rustls::TlsConnector {
    async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let domain = match webpki::DNSNameRef::try_from_ascii_str(domain) {
            Ok(d) => d,
            Err(_) => {
                // Must not be a valid domain name.
                get_dummy_dns_ref()
            }
        };

        tokio_rustls::TlsConnector::connect(&self, domain, stream)
            .await
            .map(|mut s| {
                s.get_mut().1.set_buffer_limit(8192);
                Box::new(s) as Box<dyn AsyncStream>
            })
    }
}

pub struct RustlsFactory;

impl RustlsFactory {
    pub fn new() -> Self {
        Self
    }
}

impl AsyncTlsFactory for RustlsFactory {
    fn create_acceptor(&self, cert_bytes: &[u8], key_bytes: &[u8]) -> Box<dyn AsyncTlsAcceptor> {
        let acceptor: tokio_rustls::TlsAcceptor =
            Arc::new(create_server_config(cert_bytes, key_bytes)).into();
        Box::new(acceptor)
    }

    fn create_connector(&self, verify: bool) -> Box<dyn AsyncTlsConnector> {
        let connector: tokio_rustls::TlsConnector = Arc::new(create_client_config(verify)).into();
        Box::new(connector)
    }
}

pub struct DisabledVerifier;
impl rustls::ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef<'_>,
        _ocsp: &[u8],
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}
fn get_disabled_verifier() -> Arc<DisabledVerifier> {
    static INSTANCE: SyncOnceCell<Arc<DisabledVerifier>> = SyncOnceCell::new();
    INSTANCE
        .get_or_init(|| Arc::new(DisabledVerifier {}))
        .clone()
}

fn create_client_config(verify: bool) -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();
    if !verify {
        config
            .dangerous()
            .set_certificate_verifier(get_disabled_verifier());
    }
    config
}

fn load_certs(cert_bytes: &[u8]) -> Vec<rustls::Certificate> {
    let mut reader = std::io::Cursor::new(cert_bytes);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(key_bytes: &[u8]) -> rustls::PrivateKey {
    let mut reader = std::io::Cursor::new(key_bytes);
    let pkcs8_keys = rustls::internal::pemfile::pkcs8_private_keys(&mut reader).unwrap();
    pkcs8_keys[0].clone()
}

fn create_server_config(cert_bytes: &[u8], key_bytes: &[u8]) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    let certs = load_certs(cert_bytes);
    let privkey = load_private_key(key_bytes);
    config.set_single_cert(certs, privkey).unwrap();
    config
}
