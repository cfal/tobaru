use serde::Deserialize;

use crate::hostname_util::normalize_hostname_pattern;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum SniValue {
    None,
    Any,
    Specified(String),
}

impl<'de> Deserialize<'de> for SniValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "none" => Ok(SniValue::None),
            "any" => Ok(SniValue::Any),
            _ => {
                let normalized =
                    normalize_hostname_pattern(&s).map_err(serde::de::Error::custom)?;
                Ok(SniValue::Specified(normalized))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deser(s: &str) -> Result<SniValue, String> {
        serde_json::from_value::<SniValue>(serde_json::Value::String(s.to_string()))
            .map_err(|e| e.to_string())
    }

    #[test]
    fn none_variant() {
        assert_eq!(deser("none").unwrap(), SniValue::None);
    }

    #[test]
    fn any_variant() {
        assert_eq!(deser("any").unwrap(), SniValue::Any);
    }

    #[test]
    fn specified_normalizes_and_wraps() {
        assert_eq!(
            deser("example.com.").unwrap(),
            SniValue::Specified("example.com".into())
        );
    }

    #[test]
    fn specified_rejects_invalid() {
        assert!(deser("example..com").is_err());
    }
}
