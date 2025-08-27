use serde::{Deserialize, Deserializer};
use std::str::FromStr;

#[derive(Debug, Deserialize, Clone)]
pub struct UploadConfig {
    pub dir: String,
    #[serde(deserialize_with = "deserialize_u32")]
    pub max_size: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub image_max_width: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub image_max_height: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub image_quality: u32,
    pub generate_thumbnails: bool,
    #[serde(deserialize_with = "deserialize_u32")]
    pub thumbnail_size: u32,
    pub allowed_types: Vec<String>,
}

fn deserialize_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u32::from_str(&s).map_err(serde::de::Error::custom)
}
