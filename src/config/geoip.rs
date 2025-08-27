use serde::{Deserialize, Deserializer};
use std::str::FromStr;

#[derive(Debug, Deserialize, Clone)]
pub struct GeoIPConfig {
    pub enabled: bool,
    pub cache_enabled: bool,
    pub api_endpoint: String,
    #[serde(deserialize_with = "deserialize_u64")]
    pub timeout_seconds: u64,
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u64::from_str(&s).map_err(serde::de::Error::custom)
}
