use serde::{Deserialize, Deserializer};
use std::path::PathBuf;
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

impl UploadConfig {
    /// Get the absolute path for the upload directory
    pub fn get_absolute_upload_dir(&self) -> PathBuf {
        let path = PathBuf::from(&self.dir);
        if path.is_relative() {
            // Resolve relative path to absolute path from current working directory
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

            // Log the path resolution for debugging
            log::info!(
                "Upload config: relative path '{}' resolved to absolute path '{:?}' from current dir '{:?}'",
                self.dir,
                current_dir.join(&path),
                current_dir
            );

            // Simple path resolution without canonicalize to avoid Windows path prefix issues
            current_dir.join(&path)
        } else {
            log::info!("Upload config: using absolute path '{:?}'", path);
            path
        }
    }

    /// Get the absolute path for a file in the upload directory
    pub fn get_absolute_file_path(&self, filename: &str) -> PathBuf {
        let file_path = self.get_absolute_upload_dir().join(filename);
        log::debug!(
            "File path resolved: '{:?}' for filename '{}'",
            file_path,
            filename
        );
        file_path
    }
}

fn deserialize_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u32::from_str(&s).map_err(serde::de::Error::custom)
}
