use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

fn get_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTANCE: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}

fn get_supported_algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
    get_crypto_provider().signature_verification_algorithms
}

fn get_root_cert_store() -> Arc<rustls::RootCertStore> {
    static INSTANCE: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            Arc::new(root_store)
        })
        .clone()
}

fn create_client_config(
    verify: bool,
    client_cert: Option<(Vec<u8>, Vec<u8>)>,
    server_fingerprints: Vec<String>,
) -> rustls::ClientConfig {
    let builder = rustls::ClientConfig::builder_with_provider(get_crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap();

    let builder = if verify {
        let webpki_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            get_root_cert_store(),
            get_crypto_provider(),
        )
        .build()
        .unwrap();
        if !server_fingerprints.is_empty() {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ServerFingerprintVerifier {
                    supported_algs: get_supported_algorithms(),
                    server_fingerprints: process_fingerprints(&server_fingerprints).unwrap(),
                    webpki_verifier: Some(Arc::into_inner(webpki_verifier).unwrap()),
                }))
        } else {
            builder.with_root_certificates(get_root_cert_store().clone())
        }
    } else if !server_fingerprints.is_empty() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerFingerprintVerifier {
                supported_algs: get_supported_algorithms(),
                server_fingerprints: process_fingerprints(&server_fingerprints).unwrap(),
                webpki_verifier: None,
            }))
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(get_disabled_verifier())
    };

    if let Some((cert_bytes, key_bytes)) = client_cert {
        let certs = load_certs(&cert_bytes);
        let private_key = load_private_key(&key_bytes);
        builder
            .with_client_auth_cert(certs, private_key)
            .expect("Could not parse client certificate")
    } else {
        builder.with_no_client_auth()
    }
}

fn get_client_config(verify: bool) -> Arc<rustls::ClientConfig> {
    static VERIFIED_INSTANCE: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static UNVERIFIED_INSTANCE: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    if verify {
        VERIFIED_INSTANCE
            .get_or_init(|| Arc::new(create_client_config(true, None, vec![])))
            .clone()
    } else {
        UNVERIFIED_INSTANCE
            .get_or_init(|| Arc::new(create_client_config(false, None, vec![])))
            .clone()
    }
}

pub fn create_client_config_with_cert(
    verify: bool,
    client_cert: Option<(Vec<u8>, Vec<u8>)>,
    alpn_protocols: Vec<Vec<u8>>,
    enable_sni: bool,
    server_fingerprints: Vec<String>,
) -> Arc<rustls::ClientConfig> {
    let mut config = create_client_config(verify, client_cert, server_fingerprints);
    config.alpn_protocols = alpn_protocols;
    config.enable_sni = enable_sni;
    Arc::new(config)
}

#[derive(Debug)]
pub struct DisabledVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

fn get_disabled_verifier() -> Arc<DisabledVerifier> {
    static INSTANCE: OnceLock<Arc<DisabledVerifier>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            Arc::new(DisabledVerifier {
                supported_algs: get_supported_algorithms(),
            })
        })
        .clone()
}

#[derive(Debug)]
pub struct ServerFingerprintVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    server_fingerprints: BTreeSet<Vec<u8>>,
    webpki_verifier: Option<rustls::client::WebPkiServerVerifier>,
}

impl rustls::client::danger::ServerCertVerifier for ServerFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(ref webpki_verifier) = self.webpki_verifier {
            let _ = webpki_verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }

        let fingerprint =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref();

        if self.server_fingerprints.contains(fingerprint_bytes) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(format!(
                "unknown server fingerprint: {hex_fingerprint}"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

pub fn load_certs(cert_bytes: &[u8]) -> Vec<CertificateDer<'static>> {
    let mut reader = std::io::Cursor::new(cert_bytes);
    let mut certs = vec![];
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        if let rustls_pemfile::Item::X509Certificate(cert) = item.unwrap() {
            certs.push(cert.into_owned());
        }
    }
    if certs.is_empty() {
        panic!("No certs found");
    }
    certs
}

pub fn load_private_key(key_bytes: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(key_bytes).unwrap()
}

#[derive(Debug)]
struct AlwaysResolvesServerCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for AlwaysResolvesServerCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub fn create_server_config(
    certs: Vec<CertificateDer<'static>>,
    private_key: &PrivateKeyDer<'static>,
    alpn_protocols: Vec<Vec<u8>>,
    client_fingerprints: &[String],
    client_ca_certs: &[Vec<u8>],
) -> rustls::ServerConfig {
    let signing_key = get_crypto_provider()
        .key_provider
        .load_private_key(private_key.clone_key())
        .unwrap();
    let certified_key = Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key));

    let webpki_verifier = if client_ca_certs.is_empty() {
        None
    } else {
        let mut store = rustls::RootCertStore::empty();
        for ca_bytes in client_ca_certs {
            for cert in load_certs(ca_bytes) {
                store.add(cert).unwrap();
            }
        }
        Some(
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(store),
                get_crypto_provider(),
            )
            .build()
            .unwrap(),
        )
    };

    let builder = rustls::ServerConfig::builder_with_provider(get_crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap();

    // Always wraps in ClientFingerprintVerifier even for CA-only auth, because
    // WebPkiClientVerifier's root_hint_subjects() leaks CA names to unauthenticated clients.
    let builder = if client_fingerprints.is_empty() && webpki_verifier.is_none() {
        builder.with_no_client_auth()
    } else {
        builder.with_client_cert_verifier(Arc::new(ClientFingerprintVerifier {
            supported_algs: get_supported_algorithms(),
            client_fingerprints: process_fingerprints(client_fingerprints).unwrap(),
            webpki_verifier,
        }))
    };

    let mut config = builder.with_cert_resolver(Arc::new(AlwaysResolvesServerCert(certified_key)));
    config.alpn_protocols = alpn_protocols;
    config.max_early_data_size = u32::MAX;
    config.ignore_client_order = true;
    config
}

pub fn get_dummy_server_name() -> ServerName<'static> {
    static INSTANCE: OnceLock<ServerName<'static>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| ServerName::try_from("example.com").unwrap().to_owned())
        .clone()
}

pub fn create_connector(verify: bool) -> tokio_rustls::TlsConnector {
    get_client_config(verify).into()
}

pub fn process_fingerprints(client_fingerprints: &[String]) -> std::io::Result<BTreeSet<Vec<u8>>> {
    let mut result = BTreeSet::new();

    for fingerprint in client_fingerprints {
        // Remove any colons and whitespace
        let clean_fp = fingerprint.replace(":", "").replace(" ", "");

        if clean_fp.len() % 2 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid client fingerprint, odd number of hex chars: {fingerprint}"),
            ));
        }

        let bytes = (0..clean_fp.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean_fp[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid client fingerprint, could not convert to hex: {fingerprint}"),
                )
            })?;

        result.insert(bytes);
    }

    Ok(result)
}

/// Verifies client certificates via CA chain validation and/or SHA256 fingerprint.
/// When both methods are configured, a certificate is accepted if either check passes.
#[derive(Debug)]
pub struct ClientFingerprintVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    client_fingerprints: BTreeSet<Vec<u8>>,
    webpki_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
}

impl rustls::server::danger::ClientCertVerifier for ClientFingerprintVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // Avoids leaking trusted CA names to unauthenticated clients.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if let Some(ref webpki_verifier) = self.webpki_verifier {
            if webpki_verifier
                .verify_client_cert(end_entity, intermediates, now)
                .is_ok()
            {
                return Ok(rustls::server::danger::ClientCertVerified::assertion());
            }
        }

        let fingerprint =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref();

        if self.client_fingerprints.contains(fingerprint_bytes) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(format!(
                "unknown client fingerprint: {hex_fingerprint}"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
