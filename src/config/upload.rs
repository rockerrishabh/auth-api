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
    /// Get the project root directory (where Cargo.toml is located)
    pub fn get_project_root() -> PathBuf {
        // Start from current directory and walk up to find Cargo.toml
        let mut current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        loop {
            if current.join("Cargo.toml").exists() {
                log::info!("Project root found at: {:?}", current);
                return current;
            }

            if let Some(parent) = current.parent() {
                current = parent.to_path_buf();
            } else {
                // Fallback to current directory if we can't find Cargo.toml
                log::warn!("Could not find Cargo.toml, using current directory as project root");
                return std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            }
        }
    }

    /// Get the appropriate base directory for uploads based on environment
    fn get_upload_base_dir() -> PathBuf {
        // Check if we're in a production environment
        let is_production = std::env::var("APP_ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .eq_ignore_ascii_case("production");

        if is_production {
            // In production, use absolute paths or environment-specific paths
            if let Ok(prod_path) = std::env::var("APP_UPLOAD_BASE_DIR") {
                let path = PathBuf::from(prod_path);
                log::info!("Using production upload base directory: {:?}", path);
                return path;
            } else {
                // Default production path
                let default_prod_path = PathBuf::from("/var/www/uploads");
                log::info!(
                    "Using default production upload directory: {:?}",
                    default_prod_path
                );
                return default_prod_path;
            }
        } else {
            // In development, use project root
            let project_root = Self::get_project_root();
            log::info!(
                "Using development upload base directory (project root): {:?}",
                project_root
            );
            return project_root;
        }
    }

    /// Get the absolute path for the upload directory
    pub fn get_absolute_upload_dir(&self) -> PathBuf {
        let path = PathBuf::from(&self.dir);
        if path.is_relative() {
            // Use environment-appropriate base directory
            let base_dir = Self::get_upload_base_dir();

            // Create the absolute path from base directory
            let absolute_path = base_dir.join(&path);

            // Log the path resolution for debugging
            log::info!(
                "Upload config: relative path '{}' resolved to absolute path '{:?}' from base dir '{:?}' (platform: {}, environment: {})",
                self.dir,
                absolute_path,
                base_dir,
                if cfg!(windows) { "Windows" } else { "Unix/Linux" },
                std::env::var("APP_ENVIRONMENT").unwrap_or_else(|_| "development".to_string())
            );

            absolute_path
        } else {
            log::info!(
                "Upload config: using absolute path '{:?}' (platform: {}, environment: {})",
                path,
                if cfg!(windows) {
                    "Windows"
                } else {
                    "Unix/Linux"
                },
                std::env::var("APP_ENVIRONMENT").unwrap_or_else(|_| "development".to_string())
            );
            path
        }
    }

    /// Get the absolute path for a file in the upload directory
    pub fn get_absolute_file_path(&self, filename: &str) -> PathBuf {
        let file_path = self.get_absolute_upload_dir().join(filename);

        // Don't normalize paths for file system operations - use native format
        // This ensures consistency between saving and reading files
        log::debug!(
            "File path resolved: '{:?}' for filename '{}' on {}",
            file_path,
            filename,
            if cfg!(windows) {
                "Windows"
            } else {
                "Unix/Linux"
            }
        );

        file_path
    }

    /// Ensure the upload directory exists and has correct permissions
    pub async fn ensure_upload_directory(&self) -> std::io::Result<()> {
        let upload_dir = self.get_absolute_upload_dir();

        // Create the directory if it doesn't exist
        if !upload_dir.exists() {
            log::info!("Creating upload directory: {:?}", upload_dir);
            tokio::fs::create_dir_all(&upload_dir).await?;
            log::info!("Upload directory created successfully: {:?}", upload_dir);
        } else {
            log::debug!("Upload directory already exists: {:?}", upload_dir);
        }

        Ok(())
    }
}

fn deserialize_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u32::from_str(&s).map_err(serde::de::Error::custom)
}
