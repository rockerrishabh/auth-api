use actix_web::{get, post, web, web::Data, HttpResponse, Result};
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
        model::{EmailVerificationToken, NewEmailVerificationToken, User},
        schema::{email_verification_tokens, users},
        AppState,
    },
    mail::EmailService,
    utils::password::PasswordService,
};

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid or expired token")]
    InvalidToken,
    #[error("Token already used")]
    TokenUsed,
    #[error("Email already verified")]
    AlreadyVerified,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Email sending error: {0}")]
    EmailError(String),
    #[error("Token generation error: {0}")]
    TokenError(String),
}

impl VerificationError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            VerificationError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found",
                "message": "User account not found"
            })),
            VerificationError::InvalidToken | VerificationError::TokenUsed => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid token",
                    "message": "Verification token is invalid, expired, or already used"
                }))
            }
            VerificationError::AlreadyVerified => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Already verified",
                    "message": "Email address is already verified"
                }))
            }
            VerificationError::DatabaseError(_)
            | VerificationError::EmailError(_)
            | VerificationError::TokenError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct VerificationResponse {
    pub message: String,
}

#[get("/verify")]
pub async fn verify_email(
    query: web::Query<std::collections::HashMap<String, String>>,
    pool: Data<AppState>,
    config: Data<AppConfig>,
    email_service: Data<EmailService>,
) -> Result<HttpResponse> {
    let token = query.get("token").cloned().unwrap_or_default();

    if token.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Missing token",
            "message": "Verification token is required"
        })));
    }

    info!("Email verification attempt");

    match handle_verify_email(token, &pool, &config, &email_service).await {
        Ok(response) => {
            info!("Email verification successful");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Email verification failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

#[post("/resend-verification")]
pub async fn resend_verification(
    request: web::Json<ResendVerificationRequest>,
    pool: Data<AppState>,
    config: Data<AppConfig>,
    email_service: Data<EmailService>,
) -> Result<HttpResponse> {
    info!("Resend verification request for email: {}", request.email);

    match handle_resend_verification(request.into_inner(), &pool, &config, &email_service).await {
        Ok(response) => {
            info!("Verification email resent");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Resend verification failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_verify_email(
    token: String,
    pool: &AppState,
    config: &AppConfig,
    email_service: &EmailService,
) -> Result<VerificationResponse, VerificationError> {
    // Verify the JWT verification token
    let token_data = config
        .jwt
        .verify_token(&token)
        .map_err(|_| VerificationError::InvalidToken)?;

    // Check if this is an email verification token
    if token_data.claims.purpose != crate::config::TokenType::EmailVerification {
        return Err(VerificationError::InvalidToken);
    }

    let user_id = &token_data.claims.sub;

    // Get database connection
    let mut conn = pool
        .db
        .get()
        .map_err(|e| VerificationError::DatabaseError(e.to_string()))?;

    // Check if user exists and is not already verified
    let user = users::table
        .filter(users::id.eq(&user_id))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| VerificationError::DatabaseError(e.to_string()))?
        .ok_or(VerificationError::UserNotFound)?;

    if user.email_verified {
        return Err(VerificationError::AlreadyVerified);
    }

    // Find verification tokens for this user
    let stored_tokens: Vec<EmailVerificationToken> = email_verification_tokens::table
        .filter(email_verification_tokens::user_id.eq(&user_id))
        .select(EmailVerificationToken::as_select())
        .load(&mut conn)
        .map_err(|e| VerificationError::DatabaseError(e.to_string()))?;

    // Find a matching token by checking if any stored hash matches the current token
    let mut matching_token: Option<&EmailVerificationToken> = None;
    for stored_token in &stored_tokens {
        if PasswordService::verify_password(&token, &stored_token.token_hash).unwrap_or(false) {
            matching_token = Some(stored_token);
            break;
        }
    }

    let verification_token = matching_token.ok_or(VerificationError::InvalidToken)?;

    // Check if token is already used
    if verification_token.used {
        return Err(VerificationError::TokenUsed);
    }

    // Check if token is expired
    if verification_token.expires_at <= Utc::now() {
        return Err(VerificationError::InvalidToken);
    }

    let token_id = verification_token.id;

    // Mark user as verified
    diesel::update(users::table.filter(users::id.eq(&user_id)))
        .set(users::email_verified.eq(true))
        .execute(&mut conn)
        .map_err(|e| VerificationError::DatabaseError(e.to_string()))?;

    // Mark the verification token as used
    diesel::update(
        email_verification_tokens::table.filter(email_verification_tokens::id.eq(&token_id)),
    )
    .set(email_verification_tokens::used.eq(true))
    .execute(&mut conn)
    .map_err(|e| VerificationError::DatabaseError(e.to_string()))?;

    // Clean up old verification tokens
    cleanup_old_verification_tokens(&user_id, &mut conn).await?;

    // Get the updated user to send confirmation email
    let updated_user = users::table
        .filter(users::id.eq(&user_id))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .map_err(|e| VerificationError::DatabaseError(e.to_string()))?;

    // Send verification confirmation email
    if let Err(e) = email_service.send_verification_confirmation_email(&updated_user) {
        // Log the error but don't fail the verification
        error!("Failed to send verification confirmation email: {}", e);
    }

    Ok(VerificationResponse {
        message: "Email verified successfully".to_string(),
    })
}

async fn handle_resend_verification(
    request: ResendVerificationRequest,
    pool: &AppState,
    config: &AppConfig,
    email_service: &EmailService,
) -> Result<VerificationResponse, VerificationError> {
    let mut conn = pool
        .db
        .get()
        .map_err(|e| VerificationError::DatabaseError(e.to_string()))?;

    // Find user by email
    let user = users::table
        .filter(users::email.eq(&request.email))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| VerificationError::DatabaseError(e.to_string()))?
        .ok_or(VerificationError::UserNotFound)?;

    if user.email_verified {
        return Err(VerificationError::AlreadyVerified);
    }

    // Clean old tokens BEFORE inserting a new one
    cleanup_old_verification_tokens(&user.id, &mut conn).await?;

    // Generate verification token
    let verification_token = config
        .jwt
        .generate_email_verification_token(user.id, &user.email)
        .map_err(|e| VerificationError::TokenError(e.to_string()))?;

    // Hash the token before storing
    let token_hash = PasswordService::hash_password(&verification_token)
        .map_err(|e| VerificationError::TokenError(e.to_string()))?;

    let new_verification_token = NewEmailVerificationToken {
        user_id: user.id,
        token_hash: &token_hash,
        expires_at: Utc::now() + Duration::seconds(config.jwt.verification_token_expires_in),
    };

    diesel::insert_into(email_verification_tokens::table)
        .values(&new_verification_token)
        .execute(&mut conn)
        .map_err(|e| VerificationError::DatabaseError(e.to_string()))?;

    // Send email using same method as registration
    email_service
        .send_verification_email(
            &user.name,
            &user.email,
            &verification_token,
            &config.server.frontend_url, // <-- you may need to pass frontend_url via config
        )
        .map_err(|e| VerificationError::EmailError(e.to_string()))?;

    Ok(VerificationResponse {
        message: "Verification email sent successfully".to_string(),
    })
}
async fn cleanup_old_verification_tokens(
    user_id: &uuid::Uuid,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
) -> Result<(), VerificationError> {
    // Delete expired or used tokens
    diesel::delete(
        email_verification_tokens::table
            .filter(email_verification_tokens::user_id.eq(user_id))
            .filter(
                email_verification_tokens::expires_at
                    .lt(Utc::now())
                    .or(email_verification_tokens::used.eq(true)),
            ),
    )
    .execute(conn)
    .map_err(|e| VerificationError::DatabaseError(e.to_string()))?;

    Ok(())
}
