use std::lazy::SyncOnceCell;
use std::sync::Arc;

use rustls::client::{ServerCertVerified, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{any_supported_type, CertifiedKey};
use rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore, ServerConfig,
};

fn create_client_config(verify: bool) -> ClientConfig {
    let builder = ClientConfig::builder().with_safe_defaults();

    if !verify {
        builder
            .with_custom_certificate_verifier(Arc::new(DisabledVerifier {}))
            .with_no_client_auth()
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

fn get_client_config(verify: bool) -> Arc<ClientConfig> {
    static VERIFIED_INSTANCE: SyncOnceCell<Arc<ClientConfig>> = SyncOnceCell::new();
    static UNVERIFIED_INSTANCE: SyncOnceCell<Arc<ClientConfig>> = SyncOnceCell::new();
    if verify {
        VERIFIED_INSTANCE
            .get_or_init(|| Arc::new(create_client_config(true)))
            .clone()
    } else {
        UNVERIFIED_INSTANCE
            .get_or_init(|| Arc::new(create_client_config(false)))
            .clone()
    }
}

pub struct DisabledVerifier;
impl rustls::client::ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn load_certs(cert_bytes: &[u8]) -> Vec<Certificate> {
    let mut reader = std::io::Cursor::new(cert_bytes);
    let mut certs = vec![];
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        match item.unwrap() {
            rustls_pemfile::Item::X509Certificate(cert) => {
                certs.push(Certificate(cert));
            }
            _ => (),
        }
    }
    if certs.is_empty() {
        panic!("No certs found");
    }
    certs
}

pub fn load_private_key(key_bytes: &[u8]) -> PrivateKey {
    let mut reader = std::io::Cursor::new(key_bytes);
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        match item.unwrap() {
            rustls_pemfile::Item::PKCS8Key(key) => {
                return PrivateKey(key);
            }
            rustls_pemfile::Item::RSAKey(key) => {
                return PrivateKey(key);
            }
            _ => (),
        }
    }
    panic!("No private key found");
}

struct AlwaysResolvesServerCert(Arc<CertifiedKey>);

impl ResolvesServerCert for AlwaysResolvesServerCert {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub fn create_server_config(
    certs: Vec<Certificate>,
    private_key: &PrivateKey,
    alpn_protocols: Vec<Vec<u8>>,
) -> ServerConfig {
    let signing_key = any_supported_type(private_key).unwrap();
    let certified_key = Arc::new(CertifiedKey::new(certs, signing_key));
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerCert(certified_key)));
    config.alpn_protocols = alpn_protocols;
    config.max_early_data_size = u32::MAX;
    config
}

pub fn get_dummy_server_name() -> ServerName {
    static INSTANCE: SyncOnceCell<ServerName> = SyncOnceCell::new();
    INSTANCE
        .get_or_init(|| ServerName::try_from("example.com").unwrap())
        .clone()
}

pub fn create_connector(verify: bool) -> tokio_rustls::TlsConnector {
    get_client_config(verify).into()
}
