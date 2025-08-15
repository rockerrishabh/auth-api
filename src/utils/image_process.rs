use std::{fs, io::Cursor, path::Path};

use actix_web::web;
use image::{DynamicImage, GenericImageView, ImageReader};
use ravif::{Encoder, Img};
use rgb::FromSlice;
use sanitize_filename::sanitize;
use uuid::Uuid;

use crate::config::UploadConfig;

#[derive(serde::Serialize, Debug)]
pub struct ProcessedImage {
    pub original_name: String,
    pub saved_name: String,
    pub avif_name: String,
    pub thumbnail_name: Option<String>,
    pub original_size: usize,
    pub avif_size: u64,
    pub thumbnail_size: Option<u64>,
    pub dimensions: ImageDimensions,
    pub thumbnail_dimensions: Option<ImageDimensions>,
}

#[derive(serde::Serialize, Debug)]
pub struct ImageDimensions {
    pub width: u32,
    pub height: u32,
}

fn resize_image(img: &DynamicImage, max_width: u32, max_height: u32) -> DynamicImage {
    let (orig_width, orig_height) = img.dimensions();
    if orig_width <= max_width && orig_height <= max_height {
        return img.clone();
    }
    let width_ratio = max_width as f32 / orig_width as f32;
    let height_ratio = max_height as f32 / orig_height as f32;
    let ratio = width_ratio.min(height_ratio);
    let new_width = (orig_width as f32 * ratio) as u32;
    let new_height = (orig_height as f32 * ratio) as u32;
    img.resize(new_width, new_height, image::imageops::FilterType::Lanczos3)
}

fn create_thumbnail(img: &DynamicImage, size: u32) -> DynamicImage {
    let (width, height) = img.dimensions();
    let min_dimension = width.min(height);
    if min_dimension <= size {
        return img.clone();
    }
    let crop_size = min_dimension;
    let x_offset = (width - crop_size) / 2;
    let y_offset = (height - crop_size) / 2;
    let cropped = img.crop_imm(x_offset, y_offset, crop_size, crop_size);
    cropped.resize_exact(size, size, image::imageops::FilterType::Lanczos3)
}

/// Encode a DynamicImage to AVIF using ravif inside a blocking thread.
/// Uses `.as_raw().as_rgb()` conversion (requires rgb::FromSlice in scope)
async fn save_avif_image(
    img: &DynamicImage,
    filepath: &str,
    quality: u8,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    // convert once on the async thread (cheap)
    let rgb_img = img.to_rgb8();
    let width = rgb_img.width() as usize;
    let height = rgb_img.height() as usize;

    // move ownership into the blocking closure
    let pixel_vec = rgb_img.into_raw(); // Vec<u8>
    let filepath = filepath.to_string();
    let quality_f = (quality.clamp(10, 100)) as f32;

    // run CPU-heavy encoding in web::block
    web::block(
        move || -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            // convert raw bytes to &[rgb::Rgb<u8>] without copying
            // requires `use rgb::FromSlice;` in scope (we have that at top)
            let rgb_slice: &[rgb::Rgb<u8>] = pixel_vec.as_slice().as_rgb();

            let img_data: Img<&[rgb::Rgb<u8>]> = Img::new(rgb_slice, width, height);

            // encoder config: speed 8 is fast — tune to taste
            let encoder = Encoder::new()
                .with_quality(quality_f)
                .with_alpha_quality(quality_f)
                .with_speed(8);

            let encoded = encoder.encode_rgb(img_data)?;
            fs::write(&filepath, &encoded.avif_file)?;
            Ok(encoded.avif_file.len() as u64)
        },
    )
    .await?
}

pub async fn image_process(
    file_data: Vec<u8>,
    original_filename: String,
    config: &UploadConfig,
) -> Result<ProcessedImage, actix_web::Error> {
    // Ensure upload directory exists
    fs::create_dir_all(&config.upload_dir).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to create upload directory: {}",
            e
        ))
    })?;

    let ext = Path::new(&original_filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // Validate file extension against allowed types
    if !config.allowed_types.contains(&ext) {
        return Err(actix_web::error::ErrorBadRequest(format!(
            "File type '{}' not allowed. Allowed types: {:?}",
            ext, config.allowed_types
        )));
    }

    // decode image
    let img = web::block(move || {
        let cursor = Cursor::new(file_data);
        let img = ImageReader::new(cursor)
            .with_guessed_format()
            .map_err(|e| format!("format guess error: {}", e))?
            .decode()
            .map_err(|e| format!("decode error: {}", e))?;
        Ok::<_, String>(img)
    })
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("blocking error: {}", e)))?
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let original_dimensions = ImageDimensions {
        width: img.width(),
        height: img.height(),
    };

    let resized_image = resize_image(&img, config.max_width, config.max_height);

    let sanitized_filename = sanitize(&original_filename);
    let uuid = Uuid::new_v4();
    let base_name = format!(
        "{}_{}",
        uuid,
        sanitized_filename.trim_end_matches(&format!(".{}", ext))
    );

    let avif_filename = format!("{}.avif", base_name);
    let avif_filepath = format!("{}/{}", config.upload_dir, avif_filename);

    let avif_size = save_avif_image(&resized_image, &avif_filepath, config.quality)
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to save AVIF: {}", e))
        })?;

    // Generate thumbnails based on configuration
    let mut thumbnail_info = None;
    if config.generate_thumbnails {
        let thumb = create_thumbnail(&resized_image, config.thumbnail_size);
        let thumb_filename = format!("{}_thumb.avif", base_name);
        let thumb_filepath = format!("{}/{}", config.upload_dir, thumb_filename);

        let thumb_size = save_avif_image(&thumb, &thumb_filepath, config.quality)
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Failed to save thumbnail AVIF: {}",
                    e
                ))
            })?;

        thumbnail_info = Some((
            thumb_filename,
            thumb_size,
            ImageDimensions {
                width: thumb.width(),
                height: thumb.height(),
            },
        ));
    }

    Ok(ProcessedImage {
        original_name: original_filename,
        saved_name: format!("{}.{}", base_name, ext),
        avif_name: avif_filename,
        thumbnail_name: thumbnail_info.as_ref().map(|(n, _, _)| n.clone()),
        original_size: resized_image.as_bytes().len(),
        avif_size,
        thumbnail_size: thumbnail_info.as_ref().map(|(_, s, _)| *s),
        dimensions: original_dimensions,
        thumbnail_dimensions: thumbnail_info.map(|(_, _, d)| d),
    })
}
