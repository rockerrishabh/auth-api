use actix_web::{put, web::Data, HttpRequest, HttpResponse, Result};
use chrono::Utc;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use log::{error, info};
use serde::{Deserialize, Serialize};
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
pub enum ProfileUpdateError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("User not found")]
    UserNotFound,
    #[error("Missing authorization header")]
    MissingAuth,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl ProfileUpdateError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            ProfileUpdateError::InvalidToken | ProfileUpdateError::MissingAuth => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Invalid token",
                    "message": "Invalid or missing authentication token"
                }))
            }
            ProfileUpdateError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found",
                "message": "User account not found"
            })),
            ProfileUpdateError::ValidationError(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Validation error",
                    "message": "Invalid input data provided"
                }))
            }
            ProfileUpdateError::DatabaseError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Deserialize)]
pub struct ProfileUpdateRequest {
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileUpdateResponse {
    pub message: String,
    pub user: UserProfile,
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

#[put("/profile")]
pub async fn update_profile(
    req: HttpRequest,
    pool: Data<AppState>,
    config: Data<AppConfig>,
    form: actix_web::web::Form<ProfileUpdateRequest>,
) -> Result<HttpResponse> {
    info!("Profile update request");

    match handle_profile_update(req, &pool, &config, form.into_inner()).await {
        Ok(response) => {
            info!("Profile updated successfully");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Profile update failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_profile_update(
    req: HttpRequest,
    pool: &AppState,
    config: &AppConfig,
    update_data: ProfileUpdateRequest,
) -> Result<ProfileUpdateResponse, ProfileUpdateError> {
    // Validate input
    if let Some(name) = &update_data.name {
        if name.trim().is_empty() || name.len() > 100 {
            return Err(ProfileUpdateError::ValidationError(
                "Name must be between 1 and 100 characters".to_string(),
            ));
        }
    }

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
        .map_err(|e| ProfileUpdateError::DatabaseError(e.to_string()))?;

    // Derive user_id from access token or a valid refresh cookie
    let user_id = if let Some(sub) = auth_sub {
        sub
    } else {
        // Fallback to refresh cookie
        let token_value = req
            .cookie("refresh_token")
            .map(|c| c.value().to_string())
            .ok_or(ProfileUpdateError::MissingAuth)?;

        // Verify JWT structure
        let token_data = config
            .jwt
            .verify_token(&token_value)
            .map_err(|_| ProfileUpdateError::InvalidToken)?;

        // Validate against DB (exists, not revoked, not expired)
        let all_stored_tokens: Vec<RefreshToken> = refresh_tokens::table
            .filter(refresh_tokens::user_id.eq(&token_data.claims.sub))
            .select(RefreshToken::as_select())
            .load(&mut conn)
            .map_err(|e| ProfileUpdateError::DatabaseError(e.to_string()))?;

        let mut matching: Option<RefreshToken> = None;
        for t in all_stored_tokens {
            if PasswordService::verify_password(&token_value, &t.token_hash).unwrap_or(false) {
                matching = Some(t);
                break;
            }
        }

        let token = matching.ok_or(ProfileUpdateError::InvalidToken)?;
        if token.revoked || token.expires_at <= Utc::now() {
            return Err(ProfileUpdateError::InvalidToken);
        }

        token_data.claims.sub
    };

    // Get user from database
    let user = users::table
        .filter(users::id.eq(&user_id))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| ProfileUpdateError::DatabaseError(e.to_string()))?
        .ok_or(ProfileUpdateError::UserNotFound)?;

    // Update user in database
    diesel::update(users::table.filter(users::id.eq(&user_id)))
        .set((
            users::name.eq(update_data.name.unwrap_or(user.name)),
            users::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .map_err(|e| ProfileUpdateError::DatabaseError(e.to_string()))?;

    // Get the updated user
    let updated_user = users::table
        .filter(users::id.eq(&user_id))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .map_err(|e| ProfileUpdateError::DatabaseError(e.to_string()))?;

    let user_profile = UserProfile {
        id: updated_user.id.to_string(),
        email: updated_user.email,
        name: updated_user.name,
        role: format!("{:?}", updated_user.role).to_lowercase(),
        avatar: updated_user.avatar,
        avatar_thumbnail: updated_user.avatar_thumbnail,
        email_verified: updated_user.email_verified,
        created_at: updated_user.created_at.to_rfc3339(),
        updated_at: updated_user.updated_at.map(|dt| dt.to_rfc3339()),
    };

    Ok(ProfileUpdateResponse {
        message: "Profile updated successfully".to_string(),
        user: user_profile,
    })
}
