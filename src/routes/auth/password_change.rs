use actix_web::{post, web, web::Data, HttpRequest, HttpResponse, Result};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
use log::{error, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    config::AppConfig,
    db::{model::User, schema::users, AppState},
    utils::password::PasswordService,
};

#[derive(Error, Debug)]
pub enum PasswordChangeError {
    #[error("User not found")]
    UserNotFound,
    #[error("Current password is incorrect")]
    IncorrectPassword,
    #[error("New password is the same as current password")]
    SamePassword,
    #[error("Password validation error: {0}")]
    PasswordError(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl PasswordChangeError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            PasswordChangeError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found",
                "message": "User account not found"
            })),
            PasswordChangeError::IncorrectPassword => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Incorrect password",
                    "message": "Current password is incorrect"
                }))
            }
            PasswordChangeError::SamePassword => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Same password",
                    "message": "New password must be different from current password"
                }))
            }
            PasswordChangeError::PasswordError(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Password validation failed",
                    "message": msg
                }))
            }
            PasswordChangeError::DatabaseError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct ChangePasswordResponse {
    pub message: String,
}

#[post("/change-password")]
pub async fn change_password(
    request: web::Json<ChangePasswordRequest>,
    pool: Data<AppState>,
    config: Data<AppConfig>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    match handle_change_password(request, &pool, &config, &req).await {
        Ok(response) => {
            info!("Password changed successfully");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Password change failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_change_password(
    request: web::Json<ChangePasswordRequest>,
    pool: &AppState,
    config: &AppConfig,
    req: &HttpRequest,
) -> Result<ChangePasswordResponse, PasswordChangeError> {
    // Try access token first
    let auth_sub = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|t| config.jwt.verify_token(t).ok())
        .map(|d| d.claims.sub);

    // Get database connection
    let mut conn = pool
        .db
        .get()
        .map_err(|e| PasswordChangeError::DatabaseError(e.to_string()))?;

    // Derive user_id from access token
    let user_id = auth_sub.ok_or(PasswordChangeError::UserNotFound)?;

    // Get the user from the database
    let user = users::table
        .filter(users::id.eq(&user_id))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .map_err(|e| {
            error!("Failed to fetch user: {}", e);
            PasswordChangeError::DatabaseError(e.to_string())
        })?;

    // Verify current password
    let password_hash = user
        .password_hash
        .as_ref()
        .ok_or(PasswordChangeError::UserNotFound)?;
    let is_current_password_valid =
        PasswordService::verify_password(&request.current_password, password_hash).map_err(
            |e| {
                error!("Failed to verify current password: {}", e);
                PasswordChangeError::DatabaseError(e.to_string())
            },
        )?;

    if !is_current_password_valid {
        return Err(PasswordChangeError::IncorrectPassword);
    }

    // Check if new password is different from current password
    let is_new_password_valid =
        PasswordService::verify_password(&request.new_password, password_hash).map_err(|e| {
            error!("Failed to verify new password: {}", e);
            PasswordChangeError::DatabaseError(e.to_string())
        })?;

    if is_new_password_valid {
        return Err(PasswordChangeError::SamePassword);
    }

    // Validate new password strength
    if request.new_password.len() < 8 {
        return Err(PasswordChangeError::PasswordError(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    // Hash the new password
    let new_password_hash = PasswordService::hash_password(&request.new_password).map_err(|e| {
        error!("Failed to hash new password: {}", e);
        PasswordChangeError::DatabaseError(e.to_string())
    })?;

    // Update the user's password in the database
    diesel::update(users::table.filter(users::id.eq(&user_id)))
        .set(users::password_hash.eq(&new_password_hash))
        .execute(&mut conn)
        .map_err(|e| {
            error!("Failed to update password: {}", e);
            PasswordChangeError::DatabaseError(e.to_string())
        })?;

    info!("Password changed successfully for user: {}", user.email);

    Ok(ChangePasswordResponse {
        message: "Password changed successfully".to_string(),
    })
}
