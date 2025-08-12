use actix_multipart::Multipart;
use actix_web::{HttpResponse, Result, post, web};
use futures_util::TryStreamExt as _;
use image::{DynamicImage, GenericImageView, ImageReader};
use ravif::{Encoder, Img};
use rgb::FromSlice; // <<-- important: provides `.as_rgb()`
use sanitize_filename::sanitize;
use serde::Deserialize;
use std::time::Instant;
use std::{fs, io::Cursor, path::Path};
use uuid::Uuid;

#[derive(Deserialize, Clone)]
pub struct UploadConfig {
    max_file_size: usize,
    allowed_extensions: Vec<String>,
    upload_dir: String,
    max_width: u32,
    max_height: u32,
    quality: u8,
    generate_thumbnails: bool,
    thumbnail_size: u32,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024,
            allowed_extensions: vec![
                "jpg".into(),
                "jpeg".into(),
                "png".into(),
                "gif".into(),
                "webp".into(),
                "bmp".into(),
                "tiff".into(),
            ],
            upload_dir: "./static".into(),
            max_width: 1920,
            max_height: 1080,
            quality: 75, // reasonable default
            generate_thumbnails: true,
            thumbnail_size: 300,
        }
    }
}

#[derive(serde::Serialize)]
struct ProcessedImage {
    original_name: String,
    saved_name: String,
    avif_name: String,
    thumbnail_name: Option<String>,
    original_size: usize,
    avif_size: u64,
    thumbnail_size: Option<u64>,
    dimensions: ImageDimensions,
    thumbnail_dimensions: Option<ImageDimensions>,
}

#[derive(serde::Serialize)]
struct ImageDimensions {
    width: u32,
    height: u32,
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

#[post("/image")]
async fn upload_image(
    mut payload: Multipart,
    config: web::Data<UploadConfig>,
) -> Result<HttpResponse> {
    // ensure directory exists (quick)
    fs::create_dir_all(&config.upload_dir)?;

    let mut uploaded_files = Vec::new();
    let mut total_original_size = 0usize;

    // iterate form fields
    while let Some(mut field) = payload.try_next().await? {
        if let Some(cd) = field.content_disposition() {
            if let Some(filename) = cd.get_filename() {
                let filename_owned = filename.to_string();
                let ext = Path::new(&filename_owned)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();

                if !config.allowed_extensions.contains(&ext) {
                    return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                        "error": format!("File type '{}' not allowed", ext)
                    })));
                }

                // collect chunks in memory (could be changed to streaming-to-disk if needed)
                let mut file_data = Vec::new();
                let mut file_size = 0usize;
                while let Some(chunk) = field.try_next().await? {
                    file_size += chunk.len();
                    total_original_size += chunk.len();
                    if file_size > config.max_file_size {
                        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                            "error": format!("File '{}' exceeds max size", filename_owned)
                        })));
                    }
                    file_data.extend_from_slice(&chunk);
                }

                // decode image (blocking-ish) inside web::block to avoid blocking async reactor
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
                .map_err(|e| {
                    actix_web::error::ErrorInternalServerError(format!("blocking error: {}", e))
                })?
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

                let original_dimensions = ImageDimensions {
                    width: img.width(),
                    height: img.height(),
                };

                // resize to limits
                let resized_image = resize_image(&img, config.max_width, config.max_height);

                // file names
                let sanitized_filename = sanitize(&filename_owned);
                let uuid = Uuid::new_v4();
                let base_name = format!(
                    "{}_{}",
                    uuid,
                    sanitized_filename.trim_end_matches(&format!(".{}", ext))
                );

                let avif_filename = format!("{}.avif", base_name);
                let avif_filepath = format!("{}/{}", config.upload_dir, avif_filename);

                // encode original and thumbnail in parallel using tokio join on two web::block futures.
                // note: web::block itself uses a blocking thread pool; we already initialized Rayon
                // at startup so any internal parallelism inside encoders will use it.
                let start = Instant::now();
                let avif_size =
                    match save_avif_image(&resized_image, &avif_filepath, config.quality).await {
                        Ok(s) => s,
                        Err(e) => {
                            return Ok(HttpResponse::InternalServerError().json(
                                serde_json::json!({
                                    "error": format!("Failed to save AVIF: {}", e)
                                }),
                            ));
                        }
                    };
                log::info!("Encoded main AVIF in {:?}", start.elapsed());

                // thumbnail (encode after or in parallel — here we do sequential for simplicity;
                // if you want to parallelize multiple files you can `tokio::join!` their save_avif_image futures)
                let mut thumbnail_info = None;
                if config.generate_thumbnails {
                    let thumb = create_thumbnail(&resized_image, config.thumbnail_size);
                    let thumb_filename = format!("{}_thumb.avif", base_name);
                    let thumb_filepath = format!("{}/{}", config.upload_dir, thumb_filename);

                    let thumb_size =
                        match save_avif_image(&thumb, &thumb_filepath, config.quality).await {
                            Ok(s) => s,
                            Err(e) => {
                                return Ok(HttpResponse::InternalServerError().json(
                                    serde_json::json!({
                                        "error": format!("Failed to save thumbnail AVIF: {}", e)
                                    }),
                                ));
                            }
                        };

                    thumbnail_info = Some((
                        thumb_filename,
                        thumb_size,
                        ImageDimensions {
                            width: thumb.width(),
                            height: thumb.height(),
                        },
                    ));
                }

                uploaded_files.push(ProcessedImage {
                    original_name: filename_owned,
                    saved_name: format!("{}.{}", base_name, ext),
                    avif_name: avif_filename,
                    thumbnail_name: thumbnail_info.as_ref().map(|(n, _, _)| n.clone()),
                    original_size: file_size,
                    avif_size,
                    thumbnail_size: thumbnail_info.as_ref().map(|(_, s, _)| *s),
                    dimensions: original_dimensions,
                    thumbnail_dimensions: thumbnail_info.map(|(_, _, d)| d),
                });
            }
        }
    }

    if uploaded_files.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No files uploaded"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Images processed and uploaded successfully",
        "files": uploaded_files,
        "total_original_size": total_original_size
    })))
}
