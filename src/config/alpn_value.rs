use serde::Deserialize;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum AlpnValue {
    None,
    Any,
    Specified(String),
}

impl<'de> Deserialize<'de> for AlpnValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "none" => Ok(AlpnValue::None),
            "any" => Ok(AlpnValue::Any),
            _ => Ok(AlpnValue::Specified(s)),
        }
    }
}
