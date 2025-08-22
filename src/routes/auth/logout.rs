use actix_web::{cookie::Cookie, post, web, web::Data, HttpRequest, HttpResponse, Result};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use log::{error, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    config::AppConfig,
    db::{schema::refresh_tokens, AppState},
    utils::password::PasswordService,
};

#[derive(Error, Debug)]
pub enum LogoutError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Missing authorization header")]
    MissingAuth,
}

impl LogoutError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            LogoutError::InvalidToken | LogoutError::MissingAuth => HttpResponse::Unauthorized()
                .json(serde_json::json!({
                    "error": "Invalid token",
                    "message": "Invalid or missing authentication token"
                })),
            LogoutError::DatabaseError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub logout_all: Option<bool>,
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub message: String,
}

#[post("/logout")]
pub async fn logout_user(
    req: HttpRequest,
    logout_data: web::Json<LogoutRequest>,
    pool: Data<AppState>,
    config: Data<AppConfig>,
) -> Result<HttpResponse> {
    info!("Logout attempt");

    match handle_logout(req, logout_data.into_inner(), &pool, &config).await {
        Ok(response) => {
            info!("Logout successful");

            // Create multiple cookies to clear the refresh token in different scenarios
            // Clear cookie with secure flag (for HTTPS)
            let secure_cookie = Cookie::build("refresh_token", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .http_only(true)
                .secure(true)
                .same_site(actix_web::cookie::SameSite::Strict)
                .finish();

            // Clear cookie without secure flag (for HTTP/localhost)
            let insecure_cookie = Cookie::build("refresh_token", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .http_only(true)
                .secure(false)
                .same_site(actix_web::cookie::SameSite::Strict)
                .finish();

            // Clear cookie with domain (for subdomains)
            let domain_cookie = Cookie::build("refresh_token", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .http_only(true)
                .secure(false)
                .same_site(actix_web::cookie::SameSite::Lax)
                .finish();

            Ok(HttpResponse::Ok()
                .cookie(secure_cookie)
                .cookie(insecure_cookie)
                .cookie(domain_cookie)
                .json(response))
        }
        Err(e) => {
            error!("Logout failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_logout(
    req: HttpRequest,
    logout_data: LogoutRequest,
    pool: &AppState,
    config: &AppConfig,
) -> Result<LogoutResponse, LogoutError> {
    // Extract access token from Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(LogoutError::MissingAuth)?;

    // Verify access token to get user ID
    let token_data = config
        .jwt
        .verify_token(auth_header)
        .map_err(|_| LogoutError::InvalidToken)?;

    let user_id = &token_data.claims.sub;

    // Get database connection
    let mut conn = pool
        .db
        .get()
        .map_err(|e| LogoutError::DatabaseError(e.to_string()))?;

    if logout_data.logout_all.unwrap_or(false) {
        // Revoke all refresh tokens for this user
        diesel::update(
            refresh_tokens::table
                .filter(refresh_tokens::user_id.eq(&user_id))
                .filter(refresh_tokens::revoked.eq(false)),
        )
        .set(refresh_tokens::revoked.eq(true))
        .execute(&mut conn)
        .map_err(|e| LogoutError::DatabaseError(e.to_string()))?;

        info!("All sessions logged out for user: {}", user_id);

        Ok(LogoutResponse {
            message: "Successfully logged out from all devices".to_string(),
        })
    } else {
        // Get refresh token from cookie
        let refresh_token = req.cookie("refresh_token").map(|c| c.value().to_string());

        if let Some(refresh_token) = refresh_token {
            // Revoke specific refresh token
            let stored_tokens: Vec<(uuid::Uuid, String)> = refresh_tokens::table
                .filter(refresh_tokens::user_id.eq(&user_id))
                .filter(refresh_tokens::revoked.eq(false))
                .select((refresh_tokens::id, refresh_tokens::token_hash))
                .load(&mut conn)
                .map_err(|e| LogoutError::DatabaseError(e.to_string()))?;

            // Find and revoke the matching token
            for (token_id, token_hash) in stored_tokens {
                if PasswordService::verify_password(&refresh_token, &token_hash).unwrap_or(false) {
                    diesel::update(refresh_tokens::table.filter(refresh_tokens::id.eq(&token_id)))
                        .set(refresh_tokens::revoked.eq(true))
                        .execute(&mut conn)
                        .map_err(|e| LogoutError::DatabaseError(e.to_string()))?;

                    info!("Specific session logged out for user: {}", user_id);

                    return Ok(LogoutResponse {
                        message: "Successfully logged out".to_string(),
                    });
                }
            }
        }

        // No refresh token found or token didn't match, just acknowledge the logout
        info!("Access token logout for user: {}", user_id);

        Ok(LogoutResponse {
            message: "Successfully logged out".to_string(),
        })
    }
}
