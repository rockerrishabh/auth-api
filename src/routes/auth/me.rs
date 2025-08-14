use actix_web::{get, web::Data, HttpResponse, Result, HttpRequest};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use log::{error, info};
use serde::Serialize;
use thiserror::Error;

use crate::{
    db::{
        model::User,
        schema::users,
        AppState,
    },
    utils::jwt::{JwtConfig, TokenType},
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
            MeError::UserNotFound => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "User not found",
                    "message": "User account not found"
                }))
            }
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

#[derive(Serialize)]
pub struct MeResponse {
    pub user: UserProfile,
}

#[get("/me")]
pub async fn get_user_profile(
    req: HttpRequest,
    pool: Data<AppState>,
    jwt_config: Data<JwtConfig>,
) -> Result<HttpResponse> {
    info!("User profile request");

    match handle_me(req, &pool, &jwt_config).await {
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
    jwt_config: &JwtConfig,
) -> Result<MeResponse, MeError> {
    // Extract access token from Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(MeError::MissingAuth)?;

    // Verify access token
    let token_data = jwt_config
        .verify_token_type(auth_header, TokenType::Access)
        .map_err(|_| MeError::InvalidToken)?;

    let user_id = uuid::Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| MeError::InvalidToken)?;

    // Get database connection
    let mut conn = pool
        .db
        .get()
        .map_err(|e| MeError::DatabaseError(e.to_string()))?;

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

    Ok(MeResponse {
        user: user_profile,
    })
}