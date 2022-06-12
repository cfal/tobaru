use serde::Deserialize;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum TlsOption {
    None,
    Any,
    Specified(String),
}

impl TlsOption {
    pub fn is_specified(&self) -> bool {
        match self {
            TlsOption::Specified(_) => true,
            _ => false,
        }
    }
    pub fn unwrap_specified(&self) -> &str {
        match self {
            TlsOption::Specified(s) => s.as_str(),
            _ => panic!("Not a hostname"),
        }
    }
}

impl<'de> Deserialize<'de> for TlsOption {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let tls_option_str = String::deserialize(deserializer)?;
        match tls_option_str.as_str() {
            "none" => Ok(TlsOption::None),
            "any" => Ok(TlsOption::Any),
            _ => Ok(TlsOption::Specified(tls_option_str)),
        }
    }
}
