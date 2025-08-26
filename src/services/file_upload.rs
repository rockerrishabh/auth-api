use crate::{
    config::AppConfig,
    error::{AuthError, AuthResult},
};
use actix_multipart::Multipart;
use futures_util::TryStreamExt;
use image::{DynamicImage, GenericImageView, ImageFormat};

use std::path::Path;
use tokio::fs;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ProcessedImage {
    pub original_path: String,
    pub thumbnail_path: String,
    pub original_size: u64,
    pub thumbnail_size: u64,
}

pub struct FileUploadService {
    config: AppConfig,
}

impl FileUploadService {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// Process and save an uploaded avatar image
    pub async fn process_avatar(&self, mut payload: Multipart) -> AuthResult<ProcessedImage> {
        let mut image_data: Option<Vec<u8>> = None;

        // Extract file data from multipart form
        while let Some(mut field) = payload.try_next().await? {
            if field.name() == Some("avatar") {
                let content_type = field.content_type().map(|m| m.to_string());

                // Validate content type
                if !self.is_valid_image_type(content_type.as_deref()) {
                    return Err(AuthError::ValidationFailed(
                        "Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.".to_string(),
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

                image_data = Some(data);
                break;
            }
        }

        let image_data = image_data
            .ok_or_else(|| AuthError::ValidationFailed("No avatar file provided".to_string()))?;

        // Generate unique filename
        let file_extension = self.get_file_extension(&image_data)?;
        let file_id = Uuid::new_v4();
        let filename = format!("{}.{}", file_id, file_extension);

        // Process and save images
        let processed_image = self
            .save_image_with_thumbnail(&filename, &image_data)
            .await?;

        Ok(processed_image)
    }

    /// Save original image and create thumbnail
    async fn save_image_with_thumbnail(
        &self,
        filename: &str,
        image_data: &[u8],
    ) -> AuthResult<ProcessedImage> {
        // Load and process image
        let img = image::load_from_memory(image_data)
            .map_err(|e| AuthError::InternalError(format!("Failed to load image: {}", e)))?;

        // Ensure upload directory exists
        fs::create_dir_all(&self.config.upload.dir)
            .await
            .map_err(|e| {
                AuthError::InternalError(format!("Failed to create upload directory: {}", e))
            })?;

        // Save original image (resized if too large)
        let original_path = format!("{}/{}", self.config.upload.dir, filename);
        let processed_img = self.resize_image_if_needed(img.clone())?;
        self.save_image(&original_path, &processed_img, &filename)?;

        // Create and save thumbnail if enabled in configuration
        let (thumbnail_filename, _thumbnail_path, thumbnail_size) =
            if self.config.upload.generate_thumbnails {
                let thumbnail_filename = format!(
                    "{}_thumb.{}",
                    filename.trim_end_matches(&format!(
                        ".{}",
                        self.get_file_extension_from_filename(filename)?
                    )),
                    "webp"
                );
                let thumbnail_path = format!("{}/{}", self.config.upload.dir, thumbnail_filename);
                let thumbnail_img = self.create_thumbnail(img)?;
                self.save_image_as_webp(&thumbnail_path, &thumbnail_img)?;

                let thumbnail_size = fs::metadata(&thumbnail_path)
                    .await
                    .map_err(|e| {
                        AuthError::InternalError(format!("Failed to get thumbnail metadata: {}", e))
                    })?
                    .len();

                (thumbnail_filename, thumbnail_path, thumbnail_size)
            } else {
                // No thumbnail generated
                ("".to_string(), "".to_string(), 0)
            };

        // Get file sizes
        let original_size = fs::metadata(&original_path)
            .await
            .map_err(|e| AuthError::InternalError(format!("Failed to get file metadata: {}", e)))?
            .len();

        Ok(ProcessedImage {
            original_path: format!("/static/{}", filename),
            thumbnail_path: if thumbnail_filename.is_empty() {
                "".to_string()
            } else {
                format!("/static/{}", thumbnail_filename)
            },
            original_size,
            thumbnail_size,
        })
    }

    /// Resize image if it exceeds maximum dimensions
    fn resize_image_if_needed(&self, img: DynamicImage) -> AuthResult<DynamicImage> {
        let (width, height) = img.dimensions();

        if width > self.config.upload.image_max_width
            || height > self.config.upload.image_max_height
        {
            // Calculate new dimensions maintaining aspect ratio
            let ratio = (self.config.upload.image_max_width as f32 / width as f32)
                .min(self.config.upload.image_max_height as f32 / height as f32);

            let new_width = (width as f32 * ratio) as u32;
            let new_height = (height as f32 * ratio) as u32;

            return Ok(img.resize(new_width, new_height, image::imageops::FilterType::Lanczos3));
        }

        Ok(img)
    }

    /// Create thumbnail from image
    fn create_thumbnail(&self, img: DynamicImage) -> AuthResult<DynamicImage> {
        let (width, height) = img.dimensions();
        let size = self.config.upload.thumbnail_size;

        // Calculate dimensions maintaining aspect ratio
        let ratio = if width > height {
            size as f32 / width as f32
        } else {
            size as f32 / height as f32
        };

        let new_width = (width as f32 * ratio) as u32;
        let new_height = (height as f32 * ratio) as u32;

        Ok(img.resize(new_width, new_height, image::imageops::FilterType::Lanczos3))
    }

    /// Save image with appropriate format
    fn save_image(&self, path: &str, img: &DynamicImage, filename: &str) -> AuthResult<()> {
        let extension = self.get_file_extension_from_filename(filename)?;

        match extension.as_str() {
            "jpg" | "jpeg" => {
                self.save_image_as_jpeg_with_quality(path, img, self.config.upload.image_quality)?;
            }
            "png" => {
                img.write_to(&mut std::fs::File::create(path)?, ImageFormat::Png)
                    .map_err(|e| AuthError::InternalError(format!("Failed to save PNG: {}", e)))?;
            }
            "gif" => {
                img.write_to(&mut std::fs::File::create(path)?, ImageFormat::Gif)
                    .map_err(|e| AuthError::InternalError(format!("Failed to save GIF: {}", e)))?;
            }
            "webp" => {
                self.save_image_as_webp(path, img)?;
            }
            "avif" => {
                self.save_image_as_avif(path, img)?;
            }
            _ => {
                // Default to AVIF for best compression
                self.save_image_as_avif(path, img)?;
            }
        }

        Ok(())
    }

    /// Save image as JPEG with custom quality
    fn save_image_as_jpeg_with_quality(
        &self,
        path: &str,
        img: &DynamicImage,
        quality: u32,
    ) -> AuthResult<()> {
        use image::codecs::jpeg::JpegEncoder;

        let output_file = std::fs::File::create(path)
            .map_err(|e| AuthError::InternalError(format!("Failed to create JPEG file: {}", e)))?;

        let encoder = JpegEncoder::new_with_quality(output_file, quality.clamp(1, 100) as u8);
        img.write_with_encoder(encoder).map_err(|e| {
            AuthError::InternalError(format!(
                "Failed to encode JPEG with quality {}: {}",
                quality, e
            ))
        })?;

        Ok(())
    }

    /// Save image as WebP format
    fn save_image_as_webp(&self, path: &str, img: &DynamicImage) -> AuthResult<()> {
        let mut file = std::fs::File::create(path)
            .map_err(|e| AuthError::InternalError(format!("Failed to create file: {}", e)))?;

        img.write_to(&mut file, ImageFormat::WebP)
            .map_err(|e| AuthError::InternalError(format!("Failed to save WebP: {}", e)))?;

        Ok(())
    }

    /// Save image as AVIF format (fallback to WebP if AVIF fails)
    fn save_image_as_avif(&self, path: &str, img: &DynamicImage) -> AuthResult<()> {
        // Feature flag for AVIF encoding - can be enabled when ravif crate is available
        #[cfg(feature = "avif-encoding")]
        {
            // Proper AVIF encoding implementation when feature is enabled
            use std::fs::File;
            use std::io::Write;

            // Convert image to RGBA8 format required by ravif
            let rgba_img = img.to_rgba8();

            // Configure AVIF encoder with quality settings
            let config = ravif::Config {
                quality: (self.config.upload.image_quality as f32).min(100.0),
                alpha_quality: (self.config.upload.image_quality as f32).min(100.0),
                speed: 4,   // Balance between speed and quality
                threads: 0, // Auto-detect thread count
            };

            // Encode the image to AVIF format
            match ravif::encode_rgba(rgba_img, img.width(), img.height(), &config) {
                Ok(avif_data) => {
                    let mut file = File::create(path).map_err(|e| {
                        AuthError::InternalError(format!("Failed to create AVIF file: {}", e))
                    })?;

                    file.write_all(&avif_data).map_err(|e| {
                        AuthError::InternalError(format!("Failed to write AVIF data: {}", e))
                    })?;

                    Ok(())
                }
                Err(e) => {
                    // Fall back to WebP if AVIF encoding fails
                    eprintln!("AVIF encoding failed, falling back to WebP: {:?}", e);
                    self.save_image_as_webp(path, img)
                }
            }
        }

        #[cfg(not(feature = "avif-encoding"))]
        {
            // Use WebP as fallback when AVIF feature is not enabled
            self.save_image_as_webp(path, img)
        }
    }

    /// Check if content type is a valid image type
    fn is_valid_image_type(&self, content_type: Option<&str>) -> bool {
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

    /// Get file extension from image data
    fn get_file_extension(&self, data: &[u8]) -> AuthResult<String> {
        match image::guess_format(data) {
            Ok(ImageFormat::Jpeg) => Ok("jpg".to_string()),
            Ok(ImageFormat::Png) => Ok("png".to_string()),
            Ok(ImageFormat::Gif) => Ok("gif".to_string()),
            Ok(ImageFormat::WebP) => Ok("webp".to_string()),
            // AVIF detection: image crate doesn't support AVIF, so we use custom signature detection
            _ => {
                // Check if it's AVIF by examining the file signature
                if data.len() >= 12 && data[0..4] == [0x66, 0x74, 0x79, 0x70] {
                    Ok("avif".to_string())
                } else {
                    Err(AuthError::ValidationFailed(
                        "Unsupported image format".to_string(),
                    ))
                }
            }
        }
    }

    /// Get file extension from filename
    fn get_file_extension_from_filename(&self, filename: &str) -> AuthResult<String> {
        Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            .ok_or_else(|| AuthError::ValidationFailed("Invalid filename".to_string()))
    }

    /// Validate filename from content disposition
    fn validate_filename(&self, filename: &str) -> AuthResult<()> {
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
