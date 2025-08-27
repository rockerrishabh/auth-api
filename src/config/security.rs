use serde::{Deserialize, Deserializer};
use std::str::FromStr;

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(deserialize_with = "deserialize_u32")]
    pub argon2_memory_cost: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub argon2_time_cost: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub argon2_parallelism: u32,
    #[serde(deserialize_with = "deserialize_u64")]
    pub session_timeout: u64,
    #[serde(deserialize_with = "deserialize_u32")]
    pub max_failed_attempts: u32,
    #[serde(deserialize_with = "deserialize_u64")]
    pub lockout_duration: u64,
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
