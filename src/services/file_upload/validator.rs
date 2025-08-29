//! File validation utilities

use crate::{
    config::AppConfig,
    error::{AuthError, AuthResult},
};
use actix_multipart::Multipart;
use futures_util::TryStreamExt;

/// File validator for handling file uploads
pub struct FileValidator<'a> {
    config: &'a AppConfig,
}

impl<'a> FileValidator<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        Self { config }
    }

    /// Extract and validate file data from multipart form
    pub async fn extract_file_data(
        &self,
        mut payload: Multipart,
        field_name: &str,
    ) -> AuthResult<Vec<u8>> {
        let mut file_data: Option<Vec<u8>> = None;

        // Extract file data from multipart form
        while let Some(mut field) = payload.try_next().await? {
            if field.name() == Some(field_name) {
                let content_type = field.content_type().map(|m| m.to_string());

                // Debug logging for multipart field
                println!("DEBUG: Processing field: {:?}", field.name());
                println!("DEBUG: Content type: {:?}", content_type);
                println!(
                    "DEBUG: Content disposition: {:?}",
                    field.content_disposition()
                );

                // If content type is None, try to infer from filename
                let inferred_content_type = if content_type.is_none() {
                    if let Some(content_disposition) = field.content_disposition() {
                        if let Some(filename) = content_disposition.get_filename() {
                            let extension = filename.split('.').last().unwrap_or("").to_lowercase();
                            match extension.as_str() {
                                "jpg" | "jpeg" => Some("image/jpeg".to_string()),
                                "png" => Some("image/png".to_string()),
                                "gif" => Some("image/gif".to_string()),
                                "webp" => Some("image/webp".to_string()),
                                "avif" => Some("image/avif".to_string()),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    content_type
                };

                println!("DEBUG: Inferred content type: {:?}", inferred_content_type);

                // Validate content type
                if !self.is_valid_image_type(inferred_content_type.as_deref()) {
                    return Err(AuthError::ValidationFailed(
                        "Invalid file type. Only JPEG, PNG, GIF, WebP, and AVIF are allowed."
                            .to_string(),
                    ));
                }

                // Read file data
                let mut data = Vec::new();
                while let Some(chunk) = field.try_next().await? {
                    data.extend_from_slice(&chunk);
                }

                // Validate file size
                if data.len() > self.config.upload.max_size as usize {
                    return Err(AuthError::ValidationFailed(format!(
                        "File too large. Maximum size is {} bytes.",
                        self.config.upload.max_size
                    )));
                }

                // Extract filename from content disposition for validation
                if let Some(content_disposition) = field.content_disposition() {
                    if let Some(fname) = content_disposition.get_filename() {
                        // Validate filename
                        self.validate_filename(fname)?;
                    }
                }

                file_data = Some(data);
                break;
            }
        }

        file_data
            .ok_or_else(|| AuthError::ValidationFailed(format!("No {} file provided", field_name)))
    }

    /// Check if content type is a valid image type
    pub fn is_valid_image_type(&self, content_type: Option<&str>) -> bool {
        if let Some(ct) = content_type {
            // Check if the content type is in the allowed types configuration
            let content_type_without_prefix = ct.strip_prefix("image/").unwrap_or(ct);

            self.config
                .upload
                .allowed_types
                .contains(&content_type_without_prefix.to_string())
        } else {
            false
        }
    }

    /// Validate filename from content disposition
    pub fn validate_filename(&self, filename: &str) -> AuthResult<()> {
        // Check filename length
        if filename.is_empty() || filename.len() > 255 {
            return Err(AuthError::ValidationFailed(
                "Filename is too long or empty".to_string(),
            ));
        }

        // Check for path traversal attempts
        if filename.contains("..") || filename.contains("/") || filename.contains("\\") {
            return Err(AuthError::ValidationFailed(
                "Invalid filename: path traversal not allowed".to_string(),
            ));
        }

        // Check for suspicious characters
        let suspicious_chars = ['<', '>', ':', '"', '|', '?', '*'];
        if filename.chars().any(|c| suspicious_chars.contains(&c)) {
            return Err(AuthError::ValidationFailed(
                "Invalid filename: contains suspicious characters".to_string(),
            ));
        }

        // Check for hidden files
        if filename.starts_with('.') {
            return Err(AuthError::ValidationFailed(
                "Invalid filename: hidden files not allowed".to_string(),
            ));
        }

        Ok(())
    }
}
