use std::lazy::SyncOnceCell;
use std::sync::Arc;

fn create_client_config(verify: bool) -> rustls::ClientConfig {
    let builder = rustls::ClientConfig::builder().with_safe_defaults();

    if !verify {
        builder
            .with_custom_certificate_verifier(Arc::new(DisabledVerifier {}))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
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

fn get_client_config(verify: bool) -> Arc<rustls::ClientConfig> {
    static VERIFIED_INSTANCE: SyncOnceCell<Arc<rustls::ClientConfig>> = SyncOnceCell::new();
    static UNVERIFIED_INSTANCE: SyncOnceCell<Arc<rustls::ClientConfig>> = SyncOnceCell::new();
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
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::client::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn load_certs(cert_bytes: &[u8]) -> Vec<rustls::Certificate> {
    let mut reader = std::io::Cursor::new(cert_bytes);
    let mut certs = vec![];
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        match item.unwrap() {
            rustls_pemfile::Item::X509Certificate(cert) => {
                certs.push(rustls::Certificate(cert));
            }
            _ => (),
        }
    }
    certs
}

fn load_private_key(key_bytes: &[u8]) -> rustls::PrivateKey {
    let mut reader = std::io::Cursor::new(key_bytes);
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        match item.unwrap() {
            rustls_pemfile::Item::PKCS8Key(key) => {
                return rustls::PrivateKey(key);
            }
            rustls_pemfile::Item::RSAKey(key) => {
                return rustls::PrivateKey(key);
            }
            _ => (),
        }
    }
    panic!("No private key found");
}

fn create_server_config(cert_bytes: &[u8], key_bytes: &[u8]) -> rustls::ServerConfig {
    let certs = load_certs(cert_bytes);
    let privkey = load_private_key(key_bytes);
    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, privkey)
        .expect("bad certificate/key");
    config.max_early_data_size = u32::MAX;
    config
}

pub fn get_dummy_server_name() -> rustls::ServerName {
    static INSTANCE: SyncOnceCell<rustls::ServerName> = SyncOnceCell::new();
    INSTANCE
        .get_or_init(|| rustls::ServerName::try_from("example.com").unwrap())
        .clone()
}

pub fn create_acceptor(cert_bytes: &[u8], key_bytes: &[u8]) -> tokio_rustls::TlsAcceptor {
    Arc::new(create_server_config(cert_bytes, key_bytes)).into()
}

pub fn create_connector(verify: bool) -> tokio_rustls::TlsConnector {
    get_client_config(verify).into()
}
