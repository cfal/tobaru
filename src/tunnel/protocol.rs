use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ALPN: &[u8] = b"tobaru-reverse/1";
pub const MAX_FRAME: usize = 4096;
pub const MAX_BUDGET_MS: u32 = 86_400_000;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Id(String);

impl Id {
    pub fn new() -> Self {
        Self(format!("{:032x}", rand::random::<u128>()))
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom("Invalid tunnel identifier"));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    Unauthorized,
    Unavailable,
    Busy,
    ConnectFailed,
    Timeout,
    Protocol,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    ControlHello {
        version: u32,
        peer: String,
        services: Vec<String>,
    },
    ControlReady {
        session_id: Id,
        services: Vec<String>,
    },
    CreateData {
        channel_id: Id,
    },
    CreateFailed {
        channel_id: Id,
        code: Code,
    },
    DataHello {
        version: u32,
        peer: String,
        session_id: Id,
        channel_id: Id,
    },
    DataReady {},
    Open {
        service: String,
        budget_ms: u32,
    },
    Ready {},
    OpenFailed {
        code: Code,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

pub fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid reverse tunnel protocol",
    )
}

impl Message {
    fn validate(&self) -> io::Result<()> {
        use crate::config::tunnel::valid_name;
        let valid = match self {
            Self::ControlHello {
                version,
                peer,
                services,
            } => *version == 1 && valid_name(peer) && valid_services(services),
            Self::DataHello { version, peer, .. } => *version == 1 && valid_name(peer),
            Self::ControlReady { services, .. } => valid_services(services),
            Self::Open { service, budget_ms } => {
                valid_name(service) && (1..=MAX_BUDGET_MS).contains(budget_ms)
            }
            _ => true,
        };
        if valid {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

fn valid_services(services: &[String]) -> bool {
    let mut names = std::collections::HashSet::new();
    services.len() <= 32
        && services
            .iter()
            .all(|s| crate::config::tunnel::valid_name(s) && names.insert(s))
}

// A cancelled partial frame read must discard its transport, never restart decoding.
pub async fn read(io: &mut (impl AsyncRead + Unpin)) -> io::Result<Message> {
    let length = io.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(invalid());
    }
    let mut bytes = vec![0; length];
    io.read_exact(&mut bytes).await?;
    let message: Message = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    message.validate()?;
    Ok(message)
}

pub async fn write(io: &mut (impl AsyncWrite + Unpin), message: &Message) -> io::Result<()> {
    message.validate()?;
    let bytes = serde_json::to_vec(message).map_err(|_| invalid())?;
    if bytes.len() > MAX_FRAME {
        return Err(invalid());
    }
    io.write_u32(bytes.len() as u32).await?;
    io.write_all(&bytes).await?;
    io.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ready_does_not_consume_server_first_bytes() {
        let (mut sender, mut receiver) = tokio::io::duplex(128);
        write(&mut sender, &Message::Ready {}).await.unwrap();
        sender.write_all(b"greeting").await.unwrap();
        assert!(matches!(
            read(&mut receiver).await.unwrap(),
            Message::Ready {}
        ));
        let mut bytes = [0; 8];
        receiver.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"greeting");
    }

    #[tokio::test]
    async fn fragmented_frames_and_invalid_lengths() {
        let mut frame = Vec::new();
        write(&mut frame, &Message::Ping { nonce: 7 })
            .await
            .unwrap();
        for split in 0..=frame.len() {
            let (mut sender, mut receiver) = tokio::io::duplex(1);
            let bytes = frame.clone();
            let task = tokio::spawn(async move {
                sender.write_all(&bytes[..split]).await.unwrap();
                tokio::task::yield_now().await;
                sender.write_all(&bytes[split..]).await.unwrap();
            });
            assert!(matches!(
                read(&mut receiver).await.unwrap(),
                Message::Ping { nonce: 7 }
            ));
            task.await.unwrap();
        }
        for size in [0u32, MAX_FRAME as u32 + 1, u32::MAX] {
            assert!(read(&mut size.to_be_bytes().as_slice()).await.is_err());
        }
        for end in 0..frame.len() {
            assert!(read(&mut &frame[..end]).await.is_err());
        }
    }

    #[test]
    fn messages_reject_unknown_fields_ids_and_invalid_budgets() {
        assert!(serde_json::from_str::<Message>(r#"{"type":"ready","extra":true}"#).is_err());
        assert!(serde_json::from_str::<Id>(r#""ABC""#).is_err());
        for budget_ms in [0, MAX_BUDGET_MS + 1] {
            assert!(Message::Open {
                service: "web".into(),
                budget_ms
            }
            .validate()
            .is_err());
        }
        for budget_ms in [1, 30000, MAX_BUDGET_MS] {
            Message::Open {
                service: "web".into(),
                budget_ms,
            }
            .validate()
            .unwrap();
        }
    }
}
