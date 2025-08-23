use actix_web::{cookie::Cookie, post, web::Data, HttpRequest, HttpResponse, Result};
use chrono::{Duration, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use log::{error, info};
use serde::Serialize;
use thiserror::Error;

use crate::{
    config::AppConfig,
    db::{
        model::{NewRefreshToken, RefreshToken, User},
        schema::{refresh_tokens, users},
        AppState,
    },
    utils::password::PasswordService,
};

#[derive(Error, Debug)]
pub enum RefreshError {
    #[error("Invalid refresh token")]
    InvalidToken,
    #[error("Refresh token expired")]
    TokenExpired,
    #[error("Refresh token revoked")]
    TokenRevoked,
    #[error("User not found")]
    UserNotFound,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Token generation error: {0}")]
    TokenError(String),
}

impl RefreshError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            RefreshError::InvalidToken
            | RefreshError::TokenExpired
            | RefreshError::TokenRevoked => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid token",
                "message": "Refresh token is invalid, expired, or revoked"
            })),
            RefreshError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found",
                "message": "Associated user account not found"
            })),
            RefreshError::DatabaseError(_) | RefreshError::TokenError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub message: String,
    pub access_token: String,
    pub expires_in: i64,
}

#[post("/refresh")]
pub async fn refresh_user_token(
    req: HttpRequest,
    pool: Data<AppState>,
    config: Data<AppConfig>,
) -> Result<HttpResponse> {
    info!("Token refresh attempt");

    // Extract refresh token from cookie
    let token_value = match req.cookie("refresh_token") {
        Some(cookie) => cookie.value().to_string(),
        None => return Ok(RefreshError::InvalidToken.to_http_response()),
    };

    match handle_refresh(token_value, &pool, &config).await {
        Ok((response, new_token)) => {
            info!("Token refresh successful");

            // Create new refresh token cookie
            let cookie = create_refresh_token_cookie(&new_token, &config);

            Ok(HttpResponse::Ok().cookie(cookie).json(response))
        }
        Err(e) => {
            error!("Token refresh failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_refresh(
    token_value: String,
    pool: &AppState,
    config: &AppConfig,
) -> Result<(RefreshResponse, String), RefreshError> {
    // Verify the refresh token
    let token_data = config
        .jwt
        .verify_token(&token_value)
        .map_err(|_| RefreshError::InvalidToken)?;

    let user_id = &token_data.claims.sub;

    // Get database connection
    let mut conn = pool
        .db
        .get()
        .map_err(|e| RefreshError::DatabaseError(e.to_string()))?;

    // Find all refresh tokens for this user (including expired/revoked ones for better error messages)
    let all_stored_tokens: Vec<RefreshToken> = refresh_tokens::table
        .filter(refresh_tokens::user_id.eq(&user_id))
        .select(RefreshToken::as_select())
        .load(&mut conn)
        .map_err(|e| RefreshError::DatabaseError(e.to_string()))?;

    // Find the matching token and check its status
    let mut matching_token: Option<&RefreshToken> = None;
    for stored_token in &all_stored_tokens {
        if PasswordService::verify_password(&token_value, &stored_token.token_hash).unwrap_or(false)
        {
            matching_token = Some(stored_token);
            break;
        }
    }

    let token = matching_token.ok_or(RefreshError::InvalidToken)?;

    // Check if token is revoked
    if token.revoked {
        return Err(RefreshError::TokenRevoked);
    }

    // Check if token is expired
    if token.expires_at <= Utc::now() {
        return Err(RefreshError::TokenExpired);
    }

    let token_id = token.id;

    // Get user information
    let user = users::table
        .filter(users::id.eq(&user_id))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| RefreshError::DatabaseError(e.to_string()))?
        .ok_or(RefreshError::UserNotFound)?;

    let new_access_token = config
        .jwt
        .generate_access_token(user.id, &user.email)
        .map_err(|e| RefreshError::TokenError(e.to_string()))?;

    let new_refresh_token = config
        .jwt
        .generate_refresh_token(user.id, &user.email)
        .map_err(|e| RefreshError::TokenError(e.to_string()))?;

    // Revoke the old refresh token
    diesel::update(refresh_tokens::table.filter(refresh_tokens::id.eq(&token_id)))
        .set(refresh_tokens::revoked.eq(true))
        .execute(&mut conn)
        .map_err(|e| RefreshError::DatabaseError(e.to_string()))?;

    // Store the new refresh token
    let token_hash = PasswordService::hash_password(&new_refresh_token)
        .map_err(|e| RefreshError::TokenError(e.to_string()))?;

    let new_refresh_token_record = NewRefreshToken {
        user_id: user.id,
        token_hash: &token_hash,
        expires_at: Utc::now() + Duration::seconds(config.jwt.refresh_token_expires_in),
    };

    diesel::insert_into(refresh_tokens::table)
        .values(&new_refresh_token_record)
        .execute(&mut conn)
        .map_err(|e| RefreshError::DatabaseError(e.to_string()))?;

    // Clean up old tokens
    cleanup_old_refresh_tokens(&user.id, &mut conn).await?;

    let response = RefreshResponse {
        message: "Token refreshed successfully".to_string(),
        access_token: new_access_token,
        expires_in: config.jwt.access_token_expires_in,
    };

    Ok((response, new_refresh_token))
}

async fn cleanup_old_refresh_tokens(
    user_id: &uuid::Uuid,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
) -> Result<(), RefreshError> {
    // Delete expired tokens
    diesel::delete(
        refresh_tokens::table
            .filter(refresh_tokens::user_id.eq(user_id))
            .filter(refresh_tokens::expires_at.lt(Utc::now())),
    )
    .execute(conn)
    .map_err(|e| RefreshError::DatabaseError(e.to_string()))?;

    // Keep only the 5 most recent tokens per user
    let tokens_to_keep: Vec<uuid::Uuid> = refresh_tokens::table
        .filter(refresh_tokens::user_id.eq(user_id))
        .filter(refresh_tokens::revoked.eq(false))
        .order(refresh_tokens::created_at.desc())
        .limit(5)
        .select(refresh_tokens::id)
        .load(conn)
        .map_err(|e| RefreshError::DatabaseError(e.to_string()))?;

    if !tokens_to_keep.is_empty() {
        diesel::delete(
            refresh_tokens::table
                .filter(refresh_tokens::user_id.eq(user_id))
                .filter(refresh_tokens::id.ne_all(&tokens_to_keep)),
        )
        .execute(conn)
        .map_err(|e| RefreshError::DatabaseError(e.to_string()))?;
    }

    Ok(())
}

fn create_refresh_token_cookie(token_value: &str, config: &AppConfig) -> Cookie<'static> {
    // Use refresh token expiry instead of access token expiry for cookie duration
    let max_age = config.jwt.refresh_token_expires_in;

    Cookie::build("refresh_token", token_value.to_string())
        .domain(config.jwt.domain.clone())
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(max_age))
        .http_only(true)
        .secure(true) // Only send over HTTPS
        .same_site(actix_web::cookie::SameSite::Lax)
        .finish()
}
