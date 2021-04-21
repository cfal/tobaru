use crate::async_tls::{AsyncStream, AsyncTlsAcceptor, AsyncTlsConnector, AsyncTlsFactory};

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;

#[async_trait]
impl AsyncStream for tokio_rustls::client::TlsStream<TcpStream> {}

#[async_trait]
impl AsyncStream for tokio_rustls::server::TlsStream<TcpStream> {}

#[async_trait]
impl AsyncTlsAcceptor for tokio_rustls::TlsAcceptor {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Box<dyn AsyncStream>> {
        tokio_rustls::TlsAcceptor::accept(&self, stream)
            .await
            .map(|s| Box::new(s) as Box<dyn AsyncStream>)
    }
}

#[async_trait]
impl AsyncTlsConnector for tokio_rustls::TlsConnector {
    async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let domain = webpki::DNSNameRef::try_from_ascii_str(domain)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        tokio_rustls::TlsConnector::connect(&self, domain, stream)
            .await
            .map(|s| Box::new(s) as Box<dyn AsyncStream>)
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

    fn create_connector(&self) -> Box<dyn AsyncTlsConnector> {
        let connector: tokio_rustls::TlsConnector = Arc::new(create_client_config()).into();
        Box::new(connector)
    }
}

fn create_client_config() -> rustls::ClientConfig {
    pub struct NoCertificateVerification;
    impl rustls::ServerCertVerifier for NoCertificateVerification {
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

    let mut config = rustls::ClientConfig::new();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
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
