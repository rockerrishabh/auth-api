//! Common types used across services

#[derive(Debug, Clone)]
pub struct ProcessedImage {
    pub original_path: String,
    pub thumbnail_path: String,
    pub original_size: u64,
    pub thumbnail_size: u64,
}
