use actix_web::{post, web, web::Data, HttpResponse, Result};
use chrono::{Duration, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl,
    SelectableHelper,
};
use log::{error, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    config::AppConfig,
    db::{
        model::{NewPasswordResetToken, PasswordResetToken, User},
        schema::{password_reset_tokens, users},
        AppState,
    },
    mail::EmailService,
    utils::password::PasswordService,
};

#[derive(Error, Debug)]
pub enum PasswordResetError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid or expired token")]
    InvalidToken,
    #[error("Token already used")]
    TokenUsed,
    #[error("Email not verified")]
    EmailNotVerified,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Email sending error: {0}")]
    EmailError(String),
    #[error("Token generation error: {0}")]
    TokenError(String),
    #[error("Password validation error: {0}")]
    PasswordError(String),
}

impl PasswordResetError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            PasswordResetError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found",
                "message": "User account not found"
            })),
            PasswordResetError::InvalidToken | PasswordResetError::TokenUsed => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid token",
                    "message": "Password reset token is invalid, expired, or already used"
                }))
            }
            PasswordResetError::EmailNotVerified => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Email not verified",
                    "message": "Please verify your email address before resetting password"
                }))
            }
            PasswordResetError::PasswordError(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Password validation failed",
                    "message": msg
                }))
            }
            PasswordResetError::DatabaseError(_)
            | PasswordResetError::EmailError(_)
            | PasswordResetError::TokenError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Deserialize)]
pub struct RequestPasswordResetRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct PasswordResetResponse {
    pub message: String,
}

#[post("/request-password-reset")]
pub async fn request_password_reset(
    request: web::Json<RequestPasswordResetRequest>,
    pool: Data<AppState>,
    config: Data<AppConfig>,
    email_service: Data<EmailService>,
) -> Result<HttpResponse> {
    info!("Password reset request for email: {}", request.email);

    match handle_request_password_reset(request.into_inner(), &pool, &config, &email_service).await
    {
        Ok(response) => {
            info!("Password reset email sent");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Password reset request failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

#[post("/reset-password")]
pub async fn reset_password(
    request: web::Json<ResetPasswordRequest>,
    pool: Data<AppState>,
    config: Data<AppConfig>,
) -> Result<HttpResponse> {
    info!("Password reset attempt");

    match handle_reset_password(request.into_inner(), &pool, &config).await {
        Ok(response) => {
            info!("Password reset successful");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Password reset failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_request_password_reset(
    request: RequestPasswordResetRequest,
    pool: &AppState,
    config: &AppConfig,
    email_service: &EmailService,
) -> Result<PasswordResetResponse, PasswordResetError> {
    let mut conn = pool
        .db
        .get()
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Find user by email
    let user = users::table
        .filter(users::email.eq(&request.email))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?
        .ok_or(PasswordResetError::UserNotFound)?;

    // Check if email is verified
    if !user.email_verified {
        return Err(PasswordResetError::EmailNotVerified);
    }

    // Clean old tokens BEFORE inserting a new one
    cleanup_old_password_reset_tokens(&user.id, &mut conn).await?;

    // Generate password reset token
    let reset_token = config
        .jwt
        .generate_password_reset_token(user.id, &user.email)
        .map_err(|e| PasswordResetError::TokenError(e.to_string()))?;

    // Hash the token before storing
    let token_hash = PasswordService::hash_password(&reset_token)
        .map_err(|e| PasswordResetError::TokenError(e.to_string()))?;

    let new_reset_token = NewPasswordResetToken {
        user_id: user.id,
        token_hash: &token_hash,
        expires_at: Utc::now() + Duration::hours(1), // 1 hour expiry for security
    };

    diesel::insert_into(password_reset_tokens::table)
        .values(&new_reset_token)
        .execute(&mut conn)
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Send password reset email
    email_service
        .send_password_reset_email(
            &user.name,
            &user.email,
            &reset_token,
            &config.server.frontend_url,
        )
        .map_err(|e| PasswordResetError::EmailError(e.to_string()))?;

    Ok(PasswordResetResponse {
        message: "Password reset email sent successfully".to_string(),
    })
}

async fn handle_reset_password(
    request: ResetPasswordRequest,
    pool: &AppState,
    config: &AppConfig,
) -> Result<PasswordResetResponse, PasswordResetError> {
    // Verify the JWT reset token
    let token_data = config
        .jwt
        .verify_token(&request.token)
        .map_err(|_| PasswordResetError::InvalidToken)?;

    // Check if this is a password reset token
    if token_data.claims.purpose != crate::config::TokenType::PasswordReset {
        return Err(PasswordResetError::InvalidToken);
    }

    let user_id = &token_data.claims.sub;

    // Validate new password
    if request.new_password.len() < 8 {
        return Err(PasswordResetError::PasswordError(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    let mut conn = pool
        .db
        .get()
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Check if user exists
    let _user = users::table
        .filter(users::id.eq(&user_id))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?
        .ok_or(PasswordResetError::UserNotFound)?;

    // Find password reset tokens for this user
    let stored_tokens: Vec<PasswordResetToken> = password_reset_tokens::table
        .filter(password_reset_tokens::user_id.eq(&user_id))
        .select(PasswordResetToken::as_select())
        .load(&mut conn)
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Find a matching token by checking if any stored hash matches the current token
    let mut matching_token: Option<&PasswordResetToken> = None;
    for stored_token in &stored_tokens {
        if PasswordService::verify_password(&request.token, &stored_token.token_hash)
            .unwrap_or(false)
        {
            matching_token = Some(stored_token);
            break;
        }
    }

    let reset_token = matching_token.ok_or(PasswordResetError::InvalidToken)?;

    // Check if token is already used
    if reset_token.used {
        return Err(PasswordResetError::TokenUsed);
    }

    // Check if token is expired
    if reset_token.expires_at <= Utc::now() {
        return Err(PasswordResetError::InvalidToken);
    }

    let token_id = reset_token.id;

    // Hash the new password
    let new_password_hash = PasswordService::hash_password(&request.new_password)
        .map_err(|e| PasswordResetError::PasswordError(e.to_string()))?;

    // Update user's password
    diesel::update(users::table.filter(users::id.eq(&user_id)))
        .set(users::password_hash.eq(&new_password_hash))
        .execute(&mut conn)
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Mark the reset token as used
    diesel::update(password_reset_tokens::table.filter(password_reset_tokens::id.eq(&token_id)))
        .set(password_reset_tokens::used.eq(true))
        .execute(&mut conn)
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Clean up old password reset tokens
    cleanup_old_password_reset_tokens(&user_id, &mut conn).await?;

    Ok(PasswordResetResponse {
        message: "Password reset successfully".to_string(),
    })
}

async fn cleanup_old_password_reset_tokens(
    user_id: &uuid::Uuid,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
) -> Result<(), PasswordResetError> {
    // Delete expired or used tokens
    diesel::delete(
        password_reset_tokens::table
            .filter(password_reset_tokens::user_id.eq(user_id))
            .filter(
                password_reset_tokens::expires_at
                    .lt(Utc::now())
                    .or(password_reset_tokens::used.eq(true)),
            ),
    )
    .execute(conn)
    .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    Ok(())
}
