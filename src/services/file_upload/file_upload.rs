use crate::config::AppConfig;
use crate::error::AuthResult;
use actix_multipart::Multipart;
use actix_web::web;

use super::types::ProcessedImage;

/// Main file upload service that orchestrates file processing
pub struct FileUploadService {
    config: AppConfig,
}

impl FileUploadService {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// Save uploaded file immediately without processing (for fast response)
    pub async fn save_uploaded_file(&self, payload: Multipart) -> AuthResult<ProcessedImage> {
        // Create validator and extract file data
        let validator = super::validator::FileValidator::new(&self.config);
        let image_data = validator.extract_file_data(payload, "avatar").await?;

        // Create image processor and generate filename
        let image_processor = super::image_processor::ImageProcessor::new(&self.config);
        let filename = image_processor.generate_filename(&image_data)?;

        // Save file immediately without processing
        let temp_image = image_processor
            .save_file_immediately(&filename, &image_data)
            .await?;

        Ok(temp_image)
    }

    /// Delete old avatar files
    pub async fn delete_old_avatars(
        &self,
        avatar_path: &str,
        thumbnail_path: &str,
    ) -> AuthResult<()> {
        let file_manager = super::file_manager::FileManager::new(&self.config);
        file_manager
            .delete_old_avatars(avatar_path, thumbnail_path)
            .await
    }

    /// Process image in background and update database
    pub async fn process_image_background(
        &self,
        user_id: uuid::Uuid,
        filename: String,
        user_service: web::Data<crate::services::core::user::UserService>,
    ) {
        // Spawn a background task for image processing
        let config = self.config.clone();
        let user_service = user_service.into_inner();

        tokio::spawn(async move {
            // Process the image
            let image_processor = super::image_processor::ImageProcessor::new(&config);
            let temp_path = config.upload.get_absolute_file_path(&filename);

            // Log the file path for debugging
            log::info!(
                "Background processing: attempting to read file from: {:?}",
                temp_path
            );

            // Read the saved file
            let image_data = match tokio::fs::read(&temp_path).await {
                Ok(data) => {
                    log::info!(
                        "Successfully read file for processing, size: {} bytes",
                        data.len()
                    );
                    data
                }
                Err(e) => {
                    log::error!("Failed to read saved file for processing: {}", e);
                    log::error!("File path attempted: {:?}", temp_path);
                    log::error!(
                        "Current working directory: {:?}",
                        std::env::current_dir()
                            .unwrap_or_else(|_| std::path::PathBuf::from("unknown"))
                    );
                    return;
                }
            };

            // Process the image
            let processed_image = match image_processor
                .process_and_save_image(&filename, &image_data)
                .await
            {
                Ok(img) => img,
                Err(e) => {
                    log::error!("Failed to process image: {}", e);
                    return;
                }
            };

            // Update user avatar paths in database
            if let Err(e) = user_service
                .update_user_avatar(user_id, &processed_image.original_path)
                .await
            {
                log::error!("Failed to update user avatar: {}", e);
                return;
            }

            if let Err(e) = user_service
                .update_user_avatar_thumbnail(user_id, &processed_image.thumbnail_path)
                .await
            {
                log::error!("Failed to update user avatar thumbnail: {}", e);
                return;
            }

            log::info!("Background image processing completed for user {}", user_id);
        });
    }
}
