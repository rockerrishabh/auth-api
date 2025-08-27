use crate::config::AppConfig;
use crate::error::AuthResult;
use actix_multipart::Multipart;

use super::types::ProcessedImage;

/// Main file upload service that orchestrates file processing
pub struct FileUploadService {
    config: AppConfig,
}

impl FileUploadService {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// Process and save an uploaded avatar image
    pub async fn process_avatar(&self, payload: Multipart) -> AuthResult<ProcessedImage> {
        // Create validator and extract file data
        let validator = super::validator::FileValidator::new(&self.config);
        let image_data = validator.extract_file_data(payload, "avatar").await?;

        // Create image processor and generate filename
        let image_processor = super::image_processor::ImageProcessor::new(&self.config);
        let filename = image_processor.generate_filename(&image_data)?;

        // Process and save images
        let processed_image = image_processor
            .process_and_save_image(&filename, &image_data)
            .await?;

        Ok(processed_image)
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
}
