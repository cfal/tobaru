use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};

use native_tls::Identity;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::X509;

pub fn create_identity(cert_path: &str, key_path: &str) -> Result<Identity> {
    let mut cert_file = File::open(cert_path)?;
    let mut cert_bytes = vec![];
    cert_file.read_to_end(&mut cert_bytes)?;

    let mut key_file = File::open(key_path)?;
    let mut key_bytes = vec![];
    key_file.read_to_end(&mut key_bytes)?;

    let pkey = PKey::private_key_from_pem(&key_bytes)?;
    let cert = X509::stack_from_pem(&cert_bytes)?.remove(0);

    let mut builder = Pkcs12::builder();
    builder.ca(Stack::<X509>::new().unwrap());

    // Empty passwords seem to cause an error:
    // { code: -25264, message: "MAC verification failed during PKCS12 import (wrong password?)" }
    let password = ".";

    let pkcs12 = builder.build(password, "pkcs12", &pkey, &cert)?;
    let pkcs12_bytes = pkcs12.to_der()?;

    Identity::from_pkcs12(&pkcs12_bytes, password).map_err(|e| Error::new(ErrorKind::Other, e))
}
