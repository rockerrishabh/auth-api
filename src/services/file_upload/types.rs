//! Common types used across services

#[derive(Debug, Clone)]
pub struct ProcessedImage {
    pub original_path: String,
    pub thumbnail_path: String,
}
