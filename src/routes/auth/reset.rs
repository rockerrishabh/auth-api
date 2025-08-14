use actix_web::{post, web, web::Data, HttpResponse, Result};
use chrono::Utc;
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use log::{error, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    db::{
        model::{NewPasswordResetToken, PasswordResetToken, User},
        schema::{password_reset_tokens, users},
        AppState,
    },
    mail::{send_message, templates::password_reset::password_reset_email, EmailConfig},
    utils::{
        jwt::{JwtConfig, TokenType},
        password::PasswordService,
    },
};

#[derive(Error, Debug)]
pub enum PasswordResetError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid or expired token")]
    InvalidToken,
    #[error("Token already used")]
    TokenUsed,
    #[error("Password validation failed: {0:?}")]
    PasswordValidation(Vec<String>),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Email sending error: {0}")]
    EmailError(String),
    #[error("Token generation error: {0}")]
    TokenError(String),
}

impl PasswordResetError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            PasswordResetError::UserNotFound => {
                // Don't reveal if user exists for security
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "If an account with that email exists, a password reset link has been sent"
                }))
            }
            PasswordResetError::InvalidToken | PasswordResetError::TokenUsed => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid token",
                    "message": "Password reset token is invalid, expired, or already used"
                }))
            }
            PasswordResetError::PasswordValidation(errors) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Password validation failed",
                    "message": "Password does not meet requirements",
                    "details": errors
                }))
            }
            PasswordResetError::DatabaseError(_) | 
            PasswordResetError::EmailError(_) | 
            PasswordResetError::TokenError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct ForgotPasswordResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct ResetPasswordResponse {
    pub message: String,
}

#[post("/forgot-password")]
pub async fn forgot_password(
    request: web::Json<ForgotPasswordRequest>,
    pool: Data<AppState>,
    jwt_config: Data<JwtConfig>,
    email_config: Data<EmailConfig>,
) -> Result<HttpResponse> {
    info!("Password reset request for email: {}", request.email);

    match handle_forgot_password(request.into_inner(), &pool, &jwt_config, &email_config).await {
        Ok(response) => {
            info!("Password reset email sent for: {}", response.message);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Forgot password failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

#[post("/reset-password")]
pub async fn reset_password(
    request: web::Json<ResetPasswordRequest>,
    pool: Data<AppState>,
    jwt_config: Data<JwtConfig>,
) -> Result<HttpResponse> {
    info!("Password reset attempt");

    match handle_reset_password(request.into_inner(), &pool, &jwt_config).await {
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

async fn handle_forgot_password(
    request: ForgotPasswordRequest,
    pool: &AppState,
    jwt_config: &JwtConfig,
    email_config: &EmailConfig,
) -> Result<ForgotPasswordResponse, PasswordResetError> {
    // Get database connection
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

    // Note: In production, you might want to always return success to prevent email enumeration
    // For now, we'll use the UserNotFound error for better error handling
    {
        // Generate password reset token
        let reset_token = jwt_config
            .generate_password_reset_token(user.id, &user.email)
            .map_err(|e| PasswordResetError::TokenError(e.to_string()))?;

        // Hash the token before storing
        let token_hash = PasswordService::hash_password(&reset_token)
            .map_err(|e| PasswordResetError::TokenError(e.to_string()))?;

        // Store the token in database
        let new_reset_token = NewPasswordResetToken {
            user_id: user.id,
            token_hash: &token_hash,
            expires_at: Utc::now() + jwt_config.password_reset_expiry,
        };

        diesel::insert_into(password_reset_tokens::table)
            .values(&new_reset_token)
            .execute(&mut conn)
            .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

        // Send password reset email
        let mail = password_reset_email(&user.name, &user.email, &reset_token);
        send_message(mail, email_config)
            .map_err(|e| PasswordResetError::EmailError(e.to_string()))?;

        // Clean up old reset tokens
        cleanup_old_reset_tokens(&user.id, &mut conn).await?;
    }

    // Always return success to prevent email enumeration
    Ok(ForgotPasswordResponse {
        message: "If an account with that email exists, a password reset link has been sent".to_string(),
    })
}

async fn handle_reset_password(
    request: ResetPasswordRequest,
    pool: &AppState,
    jwt_config: &JwtConfig,
) -> Result<ResetPasswordResponse, PasswordResetError> {
    // Validate password strength
    if let Err(errors) = PasswordService::validate_password_strength(&request.new_password) {
        return Err(PasswordResetError::PasswordValidation(errors));
    }

    // Verify the reset token
    let token_data = jwt_config
        .verify_token_type(&request.token, TokenType::PasswordReset)
        .map_err(|_| PasswordResetError::InvalidToken)?;

    let user_id = uuid::Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| PasswordResetError::InvalidToken)?;

    // Get database connection
    let mut conn = pool
        .db
        .get()
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Find all reset tokens for this user (including expired/used ones for better error messages)
    let all_stored_tokens: Vec<PasswordResetToken> = password_reset_tokens::table
        .filter(password_reset_tokens::user_id.eq(&user_id))
        .select(PasswordResetToken::as_select())
        .load(&mut conn)
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Find the matching token and check its status
    let mut matching_token: Option<&PasswordResetToken> = None;
    for stored_token in &all_stored_tokens {
        if PasswordService::verify_password(&request.token, &stored_token.token_hash)
            .unwrap_or(false)
        {
            matching_token = Some(stored_token);
            break;
        }
    }

    let token = matching_token.ok_or(PasswordResetError::InvalidToken)?;

    // Check if token is already used
    if token.used {
        return Err(PasswordResetError::TokenUsed);
    }

    // Check if token is expired
    if token.expires_at <= Utc::now() {
        return Err(PasswordResetError::InvalidToken);
    }

    let token_id = token.id;

    // Hash the new password
    let new_password_hash = PasswordService::hash_password(&request.new_password)
        .map_err(|e| PasswordResetError::TokenError(e.to_string()))?;

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

    // Revoke all refresh tokens for this user (force re-login)
    diesel::update(
        crate::db::schema::refresh_tokens::table
            .filter(crate::db::schema::refresh_tokens::user_id.eq(&user_id))
    )
    .set(crate::db::schema::refresh_tokens::revoked.eq(true))
    .execute(&mut conn)
    .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    Ok(ResetPasswordResponse {
        message: "Password has been reset successfully".to_string(),
    })
}

async fn cleanup_old_reset_tokens(
    user_id: &uuid::Uuid,
    conn: &mut diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::PgConnection>>,
) -> Result<(), PasswordResetError> {
    // Delete expired or used tokens
    diesel::delete(
        password_reset_tokens::table
            .filter(password_reset_tokens::user_id.eq(user_id))
            .filter(
                password_reset_tokens::expires_at.lt(Utc::now())
                    .or(password_reset_tokens::used.eq(true))
            )
    )
    .execute(conn)
    .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    Ok(())
}