use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

use super::protocol::{invalid, ALPN};
use crate::config::tunnel::{TunnelClientConfig, TunnelServerConfig};
use crate::rustls_util::{
    create_client_config_with_cert, create_server_config, load_certs, load_private_key,
};

pub fn socket_options(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    crate::socket_util::set_tcp_keepalive(stream, Duration::from_secs(20), Duration::from_secs(10))
}

pub fn server(config: &TunnelServerConfig) -> io::Result<Arc<rustls::ServerConfig>> {
    config.validate()?;
    let pins: Vec<_> = config
        .peers
        .values()
        .flat_map(|p| p.client_fingerprints.clone())
        .collect();
    Ok(Arc::new(create_server_config(
        load_certs(&std::fs::read(&config.server_tls.cert)?)?,
        &load_private_key(&std::fs::read(&config.server_tls.key)?)?,
        vec![ALPN.to_vec()],
        &pins,
        &[],
    )?))
}

pub fn client(config: &TunnelClientConfig) -> io::Result<tokio_rustls::TlsConnector> {
    config.validate()?;
    Ok(create_client_config_with_cert(
        config.client_tls.verify,
        Some((
            std::fs::read(&config.client_tls.cert)?,
            std::fs::read(&config.client_tls.key)?,
        )),
        vec![ALPN.to_vec()],
        true,
        config.client_tls.server_fingerprints.clone(),
    )?
    .into())
}

pub fn identity(connection: &rustls::ServerConnection) -> io::Result<Vec<u8>> {
    require_alpn(connection.alpn_protocol())?;
    let certificate = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or_else(invalid)?;
    Ok(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.as_ref())
            .as_ref()
            .to_vec(),
    )
}

pub fn require_alpn(value: Option<&[u8]>) -> io::Result<()> {
    if value == Some(ALPN) {
        Ok(())
    } else {
        Err(invalid())
    }
}
