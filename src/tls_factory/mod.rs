#[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
compile_error!("only one of tls-native or tls-rustls can be enabled.");

#[cfg(feature = "tls-native")]
mod native_tls;

#[cfg(feature = "tls-rustls")]
mod rustls;

#[cfg(feature = "tls-native")]
pub fn create_tls_factory() -> native_tls::NativeTlsFactory {
    native_tls::NativeTlsFactory::new()
}

#[cfg(feature = "tls-rustls")]
pub fn create_tls_factory() -> rustls::RustlsFactory {
    rustls::RustlsFactory::new()
}
