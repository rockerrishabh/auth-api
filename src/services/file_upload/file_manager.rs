//! File management utilities

use crate::{
    config::AppConfig,
    error::{AuthError, AuthResult},
};
use tokio::fs;

/// File manager for handling file operations
pub struct FileManager<'a> {
    config: &'a AppConfig,
}

impl<'a> FileManager<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        Self { config }
    }

    /// Delete old avatar files
    pub async fn delete_old_avatars(
        &self,
        avatar_path: &str,
        thumbnail_path: &str,
    ) -> AuthResult<()> {
        if !avatar_path.is_empty() {
            let full_path = format!(
                "{}/{}",
                self.config.upload.dir,
                avatar_path.trim_start_matches("/static/")
            );
            if fs::metadata(&full_path).await.is_ok() {
                fs::remove_file(&full_path).await.map_err(|e| {
                    AuthError::InternalError(format!("Failed to delete old avatar: {}", e))
                })?;
            }
        }

        if !thumbnail_path.is_empty() {
            let full_path = format!(
                "{}/{}",
                self.config.upload.dir,
                thumbnail_path.trim_start_matches("/static/")
            );
            if fs::metadata(&full_path).await.is_ok() {
                fs::remove_file(&full_path).await.map_err(|e| {
                    AuthError::InternalError(format!("Failed to delete old thumbnail: {}", e))
                })?;
            }
        }

        Ok(())
    }
}
