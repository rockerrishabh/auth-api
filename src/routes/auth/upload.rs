use crate::{
    db::DbPool,
    middleware::extract_user_id_from_request,
    services::{core::user::UserService, file_upload::file_upload::FileUploadService},
};
use actix_multipart::Multipart;
use actix_web::{post, web, HttpRequest, HttpResponse};
use tokio;

#[post("/avatar")]
pub async fn upload_avatar(
    pool: web::Data<DbPool>,
    config: web::Data<crate::config::AppConfig>,
    payload: Multipart,
    req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Extract user ID from JWT token
    let user_id =
        extract_user_id_from_request(&req).map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Create services
    let file_upload_service = FileUploadService::new(config.get_ref().clone());
    let user_service = UserService::new(pool.get_ref().clone());

    // Save the uploaded file immediately and get temporary paths
    let temp_image = file_upload_service.save_uploaded_file(payload).await?;

    // Update user with temporary paths immediately
    user_service
        .update_user_avatar(user_id, &temp_image.original_path)
        .await?;

    user_service
        .update_user_avatar_thumbnail(user_id, &temp_image.thumbnail_path)
        .await?;

    // Get the updated user to return immediately
    let updated_user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Process image in background (fire and forget)
    let config_clone = config.get_ref().clone();
    let pool_clone = pool.get_ref().clone();
    let user_id_clone = user_id;
    let temp_original_path = temp_image.original_path.clone();

    tokio::spawn(async move {
        // Delete old avatar files if they exist
        let file_upload_service = FileUploadService::new(config_clone);
        let user_service = UserService::new(pool_clone);

        if let Ok(Some(current_user)) = user_service.get_user_by_id(user_id_clone).await {
            if let Some(old_avatar) = &current_user.avatar {
                if let Some(old_thumbnail) = &current_user.avatar_thumbnail {
                    let _ = file_upload_service
                        .delete_old_avatars(old_avatar, old_thumbnail)
                        .await;
                }
            }
        }

        // Process the image in background
        file_upload_service
            .process_image_background(
                user_id_clone,
                temp_original_path
                    .split('/')
                    .last()
                    .unwrap_or("")
                    .to_string(),
                web::Data::new(user_service),
            )
            .await;
    });

    Ok(HttpResponse::Ok().json(updated_user))
}
