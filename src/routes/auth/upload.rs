use crate::{
    db::DbPool,
    middleware::extract_user_id_from_request,
    services::{core::user::UserService, file_upload::file_upload::FileUploadService},
};
use actix_multipart::Multipart;
use actix_web::{post, web, HttpRequest, HttpResponse};

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

    // Get current user to check for existing avatar
    let current_user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Process the uploaded avatar
    let processed_image = file_upload_service.process_avatar(payload).await?;

    // Delete old avatar files if they exist
    if let Some(old_avatar) = &current_user.avatar {
        if let Some(old_thumbnail) = &current_user.avatar_thumbnail {
            file_upload_service
                .delete_old_avatars(old_avatar, old_thumbnail)
                .await?;
        }
    }

    // Update user with new avatar paths
    user_service
        .update_user_avatar(user_id, &processed_image.original_path)
        .await?;

    user_service
        .update_user_avatar_thumbnail(user_id, &processed_image.thumbnail_path)
        .await?;

    // Get the updated user to return
    let updated_user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    Ok(HttpResponse::Ok().json(updated_user))
}
