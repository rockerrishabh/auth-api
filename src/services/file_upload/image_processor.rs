//! Image processing utilities

use crate::{
    config::AppConfig,
    error::{AuthError, AuthResult},
};
use image::{DynamicImage, GenericImageView, ImageFormat};
use std::path::Path;
use tokio::fs;
use uuid::Uuid;

/// Image processor for handling image operations
pub struct ImageProcessor<'a> {
    config: &'a AppConfig,
}

impl<'a> ImageProcessor<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        Self { config }
    }

    /// Generate unique filename with proper extension
    pub fn generate_filename(&self, image_data: &[u8]) -> AuthResult<String> {
        let file_extension = self.get_file_extension(image_data)?;
        let file_id = Uuid::new_v4();
        Ok(format!("{}.{}", file_id, file_extension))
    }

    /// Process and save image with optional thumbnail
    pub async fn process_and_save_image(
        &self,
        filename: &str,
        image_data: &[u8],
    ) -> AuthResult<super::types::ProcessedImage> {
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
        self.save_image(&original_path, &processed_img, filename)?;

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

        Ok(super::types::ProcessedImage {
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
    pub fn resize_image_if_needed(&self, img: DynamicImage) -> AuthResult<DynamicImage> {
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
    pub fn create_thumbnail(&self, img: DynamicImage) -> AuthResult<DynamicImage> {
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
    pub fn save_image(&self, path: &str, img: &DynamicImage, filename: &str) -> AuthResult<()> {
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
    pub fn save_image_as_jpeg_with_quality(
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
    pub fn save_image_as_webp(&self, path: &str, img: &DynamicImage) -> AuthResult<()> {
        let mut file = std::fs::File::create(path)
            .map_err(|e| AuthError::InternalError(format!("Failed to create file: {}", e)))?;

        img.write_to(&mut file, ImageFormat::WebP)
            .map_err(|e| AuthError::InternalError(format!("Failed to save WebP: {}", e)))?;

        Ok(())
    }

    /// Save image as AVIF format (fallback to WebP if AVIF fails)
    pub fn save_image_as_avif(&self, path: &str, img: &DynamicImage) -> AuthResult<()> {
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

    /// Get file extension from image data
    pub fn get_file_extension(&self, data: &[u8]) -> AuthResult<String> {
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
    pub fn get_file_extension_from_filename(&self, filename: &str) -> AuthResult<String> {
        Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            .ok_or_else(|| AuthError::ValidationFailed("Invalid filename".to_string()))
    }
}
