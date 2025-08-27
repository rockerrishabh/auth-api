use serde::{Deserialize, Deserializer};
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(deserialize_with = "deserialize_u32")]
    pub max_connections: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub min_connections: u32,
    #[serde(deserialize_with = "deserialize_u64")]
    pub connect_timeout: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    pub idle_timeout: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    pub max_lifetime: u64,
}

fn deserialize_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u32::from_str(&s).map_err(serde::de::Error::custom)
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u64::from_str(&s).map_err(serde::de::Error::custom)
}
