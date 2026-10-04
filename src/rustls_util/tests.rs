use super::*;

use rcgen::{CertificateParams, CertifiedKey, KeyPair};
use rustls::client::danger::ServerCertVerifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn identity() -> CertifiedKey<KeyPair> {
    rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap()
}

fn pem(identity: &CertifiedKey<KeyPair>) -> (Vec<u8>, Vec<u8>) {
    (
        identity.cert.pem().into_bytes(),
        identity.signing_key.serialize_pem().into_bytes(),
    )
}

fn fingerprint(identity: &CertifiedKey<KeyPair>) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, identity.cert.der())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn server_config(
    identity: &CertifiedKey<KeyPair>,
    fingerprints: &[String],
    ca_certs: &[Vec<u8>],
) -> rustls::ServerConfig {
    let (cert, key) = pem(identity);
    create_server_config(
        load_certs(&cert),
        &load_private_key(&key),
        vec![b"http/1.1".to_vec()],
        fingerprints,
        ca_certs,
    )
}

async fn exchange(
    mut client_config: rustls::ClientConfig,
    server_config: rustls::ServerConfig,
) -> std::io::Result<rustls::ProtocolVersion> {
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let (client_io, server_io) = tokio::io::duplex(65536);

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let client = async {
            let mut stream = connector
                .connect(ServerName::try_from("localhost").unwrap(), client_io)
                .await?;
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
            let version = stream.get_ref().1.protocol_version().unwrap();
            stream.write_all(b"ping").await?;
            stream.flush().await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            assert_eq!(response, b"ping");
            Ok::<_, std::io::Error>(version)
        };
        let server = async {
            let mut stream = acceptor.accept(server_io).await?;
            assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
            let version = stream.get_ref().1.protocol_version().unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).await?;
            stream.write_all(&request).await?;
            stream.shutdown().await?;
            Ok::<_, std::io::Error>(version)
        };
        let (client_version, server_version) = tokio::try_join!(client, server)?;
        assert_eq!(client_version, server_version);
        Ok(client_version)
    })
    .await
    .expect("TLS exchange timed out")
}

#[test]
fn loads_certificate_chain_from_mixed_pem() {
    let first = identity();
    let second = identity();
    let bundle = format!(
        "{}{}{}",
        first.cert.pem(),
        first.signing_key.serialize_pem(),
        second.cert.pem()
    );
    assert_eq!(
        load_certs(bundle.as_bytes()),
        vec![first.cert.der().clone(), second.cert.der().clone()]
    );
    assert_eq!(
        load_private_key(bundle.as_bytes()).secret_der(),
        first.signing_key.serialize_der()
    );
}

#[test]
#[should_panic(expected = "No certs found")]
fn rejects_pem_without_certificates() {
    load_certs(identity().signing_key.serialize_pem().as_bytes());
}

#[test]
#[should_panic]
fn rejects_malformed_certificate_pem() {
    load_certs(b"-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n");
}

#[test]
fn server_ca_validation_and_pin_are_both_required() {
    let server = identity();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server.cert.der().clone()).unwrap();
    let webpki_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        get_crypto_provider(),
    )
    .build()
    .unwrap();
    let mut verifier = ServerFingerprintVerifier {
        supported_algs: get_supported_algorithms(),
        server_fingerprints: process_fingerprints(&[fingerprint(&server)]).unwrap(),
        webpki_verifier: Some(Arc::into_inner(webpki_verifier).unwrap()),
    };
    let verify = |verifier: &ServerFingerprintVerifier, hostname| {
        verifier.verify_server_cert(
            server.cert.der(),
            &[],
            &ServerName::try_from(hostname).unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        )
    };
    assert!(verify(&verifier, "localhost").is_ok());
    assert!(verify(&verifier, "wrong.example").is_err());
    verifier.server_fingerprints = process_fingerprints(&["00".repeat(32)]).unwrap();
    assert!(verify(&verifier, "localhost").is_err());
}

#[tokio::test]
async fn server_verification_and_pinning() {
    let server = identity();
    for verify in [false, true] {
        for (pins, pin_matches) in [
            (vec![], true),
            (vec![fingerprint(&server)], true),
            (vec!["00".repeat(32)], false),
        ] {
            let client = create_client_config(verify, None, pins.clone());
            let result = exchange(client, server_config(&server, &[], &[])).await;
            assert_eq!(
                result.is_ok(),
                !verify && pin_matches,
                "verify={verify}, pins={pins:?}: {result:?}"
            );
            if let Ok(version) = result {
                assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
            }
        }
    }
}

#[tokio::test]
async fn tls12_handshake_and_shutdown() {
    let server = identity();
    let client = rustls::ClientConfig::builder_with_provider(get_crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(get_disabled_verifier())
        .with_no_client_auth();
    assert_eq!(
        exchange(client, server_config(&server, &[], &[]))
            .await
            .unwrap(),
        rustls::ProtocolVersion::TLSv1_2
    );
}

#[tokio::test]
async fn client_auth_accepts_ca_or_pin_but_rejects_unknown_and_anonymous() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let signing_key = KeyPair::generate().unwrap();
    let ca_client = CertifiedKey {
        cert: CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .signed_by(&signing_key, &issuer)
            .unwrap(),
        signing_key,
    };
    let pinned_client = identity();
    let unknown_client = identity();
    let server = identity();
    let pins = vec![fingerprint(&pinned_client)];
    let ca_certs = vec![ca_cert.pem().into_bytes()];

    for (pins, ca_certs, expected) in [
        (pins.clone(), vec![], [false, true, false, false]),
        (vec![], ca_certs.clone(), [true, false, false, false]),
        (pins, ca_certs, [true, true, false, false]),
    ] {
        for (client_identity, accepted) in [
            Some(&ca_client),
            Some(&pinned_client),
            Some(&unknown_client),
            None,
        ]
        .into_iter()
        .zip(expected)
        {
            let client = create_client_config(false, client_identity.map(pem), vec![]);
            let result = exchange(client, server_config(&server, &pins, &ca_certs)).await;
            assert_eq!(
                result.is_ok(),
                accepted,
                "pins={}, CAs={}, anonymous={}: {result:?}",
                pins.len(),
                ca_certs.len(),
                client_identity.is_none()
            );
        }
    }
}
