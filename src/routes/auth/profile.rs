use crate::config::AppConfig;
use crate::db::DbPool;
use crate::middleware::extract_user_id_from_request;
use crate::services::{
    core::password::PasswordChangeRequest,
    core::password::PasswordService,
    core::user::{UserResponse, UserService},
};
use actix_web::{get, put, web, HttpRequest, HttpResponse};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateProfileRequest {
    #[validate(length(min = 2, message = "Name must be at least 2 characters long"))]
    pub name: Option<String>,
    pub phone: Option<String>,
    pub avatar: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 8, message = "Current password is required"))]
    pub current_password: String,
    #[validate(length(min = 8, message = "New password must be at least 8 characters long"))]
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ProfileResponse {
    pub message: String,
    pub user: UserResponse,
}

#[get("/profile")]
pub async fn get_profile(
    pool: web::Data<DbPool>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id =
        extract_user_id_from_request(&req).map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let user = user_service.get_user_by_id(user_id).await?;

    match user {
        Some(user) => Ok(HttpResponse::Ok().json(user)),
        None => Err(crate::error::AuthError::UserNotFound),
    }
}

#[put("/profile")]
pub async fn update_profile(
    pool: web::Data<DbPool>,
    req: web::Json<UpdateProfileRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());

    // Update user profile fields
    let mut updated_user = None;

    if let Some(name) = &req.name {
        updated_user = Some(user_service.update_user_name(user_id, name).await?);
    }

    if let Some(phone) = &req.phone {
        updated_user = Some(user_service.update_user_phone(user_id, phone).await?);
    }

    if let Some(avatar) = &req.avatar {
        updated_user = Some(user_service.update_user_avatar(user_id, avatar).await?);
    }

    match updated_user {
        Some(user) => Ok(HttpResponse::Ok().json(ProfileResponse {
            message: "Profile updated successfully".to_string(),
            user,
        })),
        None => Err(crate::error::AuthError::ValidationFailed(
            "No updates provided".to_string(),
        )),
    }
}

/// Change user password
#[put("/profile/password")]
pub async fn change_password(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<ChangePasswordRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let password_service = PasswordService::new(config.get_ref().clone());

    // Get current user model (not response) to access password hash
    let user_model = {
        let mut conn = pool
            .get_ref()
            .get()
            .map_err(|e| crate::error::AuthError::DatabaseError(e.to_string()))?;
        use crate::db::schemas::users::dsl::*;
        users
            .filter(id.eq(user_id))
            .first::<crate::db::models::User>(&mut conn)
            .map_err(|_| crate::error::AuthError::UserNotFound)?
    };

    // Get the current password hash from the user
    let current_hash =
        user_model
            .password_hash
            .ok_or(crate::error::AuthError::ValidationFailed(
                "No password set for this account".to_string(),
            ))?;

    // Create a PasswordChangeRequest to use the validation method
    let password_change_request = PasswordChangeRequest {
        current_password: req.current_password.clone(),
        new_password: req.new_password.clone(),
        confirm_password: req.new_password.clone(), // Use same password for confirmation
    };

    // Use the validate_password_change method to validate the password change
    password_service.validate_password_change(&password_change_request, &current_hash)?;

    // Hash the new password
    let hashed_password = password_service.hash_password(&req.new_password)?;

    // Update user's password
    user_service
        .update_user_password(user_id, &hashed_password)
        .await?;

    Ok(HttpResponse::Ok().json(ProfileResponse {
        message: "Password changed successfully".to_string(),
        user: user_service.get_user_by_id(user_id).await?.unwrap(),
    }))
}
