use actix_web::{get, web::Data, HttpRequest, HttpResponse, Result};
use chrono::Utc;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use log::{error, info};
use serde::Serialize;
use thiserror::Error;

use crate::{
    config::AppConfig,
    db::{
        model::{RefreshToken, User},
        schema::{refresh_tokens, users},
        AppState,
    },
    utils::password::PasswordService,
};

#[derive(Error, Debug)]
pub enum MeError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("User not found")]
    UserNotFound,
    #[error("Missing authorization header")]
    MissingAuth,
    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl MeError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            MeError::InvalidToken | MeError::MissingAuth => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Invalid token",
                    "message": "Invalid or missing authentication token"
                }))
            }
            MeError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found",
                "message": "User account not found"
            })),
            MeError::DatabaseError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Serialize)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub avatar: Option<String>,
    pub avatar_thumbnail: Option<String>,
    pub email_verified: bool,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[get("/me")]
pub async fn get_user_profile(
    req: HttpRequest,
    pool: Data<AppState>,
    config: Data<AppConfig>,
) -> Result<HttpResponse> {
    info!("User profile request");

    match handle_me(req, &pool, &config).await {
        Ok(response) => {
            info!("User profile retrieved successfully");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("User profile retrieval failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_me(
    req: HttpRequest,
    pool: &AppState,
    config: &AppConfig,
) -> Result<UserProfile, MeError> {
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
        .map_err(|e| MeError::DatabaseError(e.to_string()))?;

    // Derive user_id from access token or a valid refresh cookie
    let user_id = if let Some(sub) = auth_sub {
        sub
    } else {
        // Fallback to refresh cookie
        let token_value = req
            .cookie("refresh_token")
            .map(|c| c.value().to_string())
            .ok_or(MeError::MissingAuth)?;

        // Verify JWT structure
        let token_data = config
            .jwt
            .verify_token(&token_value)
            .map_err(|_| MeError::InvalidToken)?;

        // Validate against DB (exists, not revoked, not expired)
        let all_stored_tokens: Vec<RefreshToken> = refresh_tokens::table
            .filter(refresh_tokens::user_id.eq(&token_data.claims.sub))
            .select(RefreshToken::as_select())
            .load(&mut conn)
            .map_err(|e| MeError::DatabaseError(e.to_string()))?;

        let mut matching: Option<RefreshToken> = None;
        for t in all_stored_tokens {
            if PasswordService::verify_password(&token_value, &t.token_hash).unwrap_or(false) {
                matching = Some(t);
                break;
            }
        }

        let token = matching.ok_or(MeError::InvalidToken)?;
        if token.revoked || token.expires_at <= Utc::now() {
            return Err(MeError::InvalidToken);
        }

        token_data.claims.sub
    };

    // Get user from database
    let user = users::table
        .filter(users::id.eq(&user_id))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| MeError::DatabaseError(e.to_string()))?
        .ok_or(MeError::UserNotFound)?;

    let user_profile = UserProfile {
        id: user.id.to_string(),
        email: user.email,
        name: user.name,
        role: format!("{:?}", user.role).to_lowercase(),
        avatar: user.avatar,
        avatar_thumbnail: user.avatar_thumbnail,
        email_verified: user.email_verified,
        created_at: user.created_at.to_rfc3339(),
        updated_at: user.updated_at.map(|dt| dt.to_rfc3339()),
    };

    Ok(user_profile)
}
