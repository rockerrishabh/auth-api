use actix_web::{cookie::Cookie, post, web::Data, HttpRequest, HttpResponse, Result};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use log::{error, info};
use serde::Serialize;
use thiserror::Error;

use crate::{
    config::AppConfig,
    db::{schema::refresh_tokens, AppState},
    utils::password::PasswordService,
};

#[derive(Error, Debug)]
pub enum LogoutError {
    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl LogoutError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            LogoutError::DatabaseError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub message: String,
}

#[post("/logout")]
pub async fn logout_user(
    req: HttpRequest,
    pool: Data<AppState>,
    config: Data<AppConfig>,
) -> Result<HttpResponse> {
    info!("Logout attempt");

    match handle_logout(req, &pool, &config).await {
        Ok(response) => {
            info!("Logout successful");

            // Create cookies to clear the refresh token with exact matching attributes
            // Match the attributes used in create_refresh_token_cookie
            let clear_cookie_secure = Cookie::build("refresh_token", "")
                .domain(config.jwt.domain.clone())
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .http_only(true)
                .secure(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .finish();

            Ok(HttpResponse::Ok()
                .cookie(clear_cookie_secure)
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
    pool: &AppState,
    config: &AppConfig,
) -> Result<LogoutResponse, LogoutError> {
    // Best-effort: try to derive user from Authorization header, but do not fail if missing/invalid
    let auth_sub: Option<uuid::Uuid> = req
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
        .map_err(|e| LogoutError::DatabaseError(e.to_string()))?;

    // Get refresh token from cookie
    let refresh_token = req.cookie("refresh_token").map(|c| c.value().to_string());

    if let Some(refresh_token) = refresh_token {
        // Revoke specific refresh token
        let mut query = refresh_tokens::table
            .filter(refresh_tokens::revoked.eq(false))
            .into_boxed();

        if let Some(sub) = auth_sub.as_ref() {
            query = query.filter(refresh_tokens::user_id.eq(sub));
        } else if let Ok(data) = config.jwt.verify_token(&refresh_token) {
            let sub = data.claims.sub;
            query = query.filter(refresh_tokens::user_id.eq(sub));
        }

        let stored_tokens: Vec<(uuid::Uuid, String)> = query
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

                info!("Specific session logged out");
                break;
            }
        }
    }

    // Acknowledge logout regardless of cookie presence
    info!("Logout acknowledged");
    Ok(LogoutResponse {
        message: "Successfully logged out".to_string(),
    })
}
