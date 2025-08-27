use serde::{Deserialize, Deserializer};
use std::str::FromStr;

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    #[serde(deserialize_with = "deserialize_u64")]
    pub access_token_expiry: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    pub refresh_token_expiry: u64,
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u64::from_str(&s).map_err(serde::de::Error::custom)
}
