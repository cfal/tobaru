use std::sync::Arc;
use std::sync::OnceLock;

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
        builder
            .with_root_certificates(get_root_cert_store())
            .with_no_client_auth()
    }
}

fn get_root_cert_store() -> Arc<RootCertStore> {
    static INSTANCE: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS
                    .into_iter()
                    .map(|trust_anchor| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            trust_anchor.subject.as_ref().to_vec(),
                            trust_anchor.subject_public_key_info.as_ref().to_vec(),
                            trust_anchor
                                .name_constraints
                                .as_ref()
                                .map(|nc| nc.as_ref().to_vec()),
                        )
                    })
                    .collect(),
            };
            Arc::new(root_store)
        })
        .clone()
}

fn get_client_config(verify: bool) -> Arc<ClientConfig> {
    static VERIFIED_INSTANCE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static UNVERIFIED_INSTANCE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
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
                certs.push(Certificate(cert.as_ref().to_vec()));
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
            rustls_pemfile::Item::Pkcs8Key(key) => {
                return PrivateKey(key.secret_pkcs8_der().to_vec());
            }
            rustls_pemfile::Item::Pkcs1Key(key) => {
                return PrivateKey(key.secret_pkcs1_der().to_vec());
            }
            rustls_pemfile::Item::Sec1Key(key) => {
                return PrivateKey(key.secret_sec1_der().to_vec());
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
    static INSTANCE: OnceLock<ServerName> = OnceLock::new();
    INSTANCE
        .get_or_init(|| ServerName::try_from("example.com").unwrap())
        .clone()
}

pub fn create_connector(verify: bool) -> tokio_rustls::TlsConnector {
    get_client_config(verify).into()
}
