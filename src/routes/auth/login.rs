use actix_web::{HttpResponse, Result, post, web, web::Data};
use chrono::Utc;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use log::{error, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    db::{
        AppState,
        model::{NewRefreshToken, User},
        schema::{refresh_tokens, users},
    },
    utils::{jwt::JwtConfig, password::PasswordService},
};

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Account not verified")]
    AccountNotVerified,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Token generation error: {0}")]
    TokenError(String),
    #[error("Password verification error: {0}")]
    PasswordError(String),
}

impl LoginError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            LoginError::InvalidCredentials => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Invalid credentials",
                    "message": "Email or password is incorrect"
                }))
            }
            LoginError::AccountNotVerified => HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Account not verified",
                "message": "Please verify your email address before logging in"
            })),
            LoginError::DatabaseError(_)
            | LoginError::TokenError(_)
            | LoginError::PasswordError(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub remember_me: Option<bool>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub message: String,
    pub user: UserInfo,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub avatar: Option<String>,
    pub email_verified: bool,
}

#[post("/login")]
pub async fn login_user(
    login_data: web::Json<LoginRequest>,
    pool: Data<AppState>,
    jwt_config: Data<JwtConfig>,
) -> Result<HttpResponse> {
    info!("Login attempt for email: {}", login_data.email);

    match handle_login(login_data.into_inner(), &pool, &jwt_config).await {
        Ok(response) => {
            info!("Login successful for email: {}", response.user.email);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Login failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_login(
    login_data: LoginRequest,
    pool: &AppState,
    jwt_config: &JwtConfig,
) -> Result<LoginResponse, LoginError> {
    // Get database connection
    let mut conn = pool
        .db
        .get()
        .map_err(|e| LoginError::DatabaseError(e.to_string()))?;

    // Find user by email
    let user = users::table
        .filter(users::email.eq(&login_data.email))
        .select(User::as_select())
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| LoginError::DatabaseError(e.to_string()))?
        .ok_or(LoginError::InvalidCredentials)?;

    // Check if user has a password (OAuth users might not)
    let password_hash = user
        .password_hash
        .as_ref()
        .ok_or(LoginError::InvalidCredentials)?;

    // Verify password
    let is_valid = PasswordService::verify_password(&login_data.password, password_hash)
        .map_err(|e| LoginError::PasswordError(e.to_string()))?;

    if !is_valid {
        return Err(LoginError::InvalidCredentials);
    }

    // Check if email is verified
    if !user.email_verified {
        return Err(LoginError::AccountNotVerified);
    }

    // Generate tokens
    let role_str = format!("{:?}", user.role).to_lowercase();

    let access_token = jwt_config
        .generate_access_token(user.id, &user.email, &role_str)
        .map_err(|e| LoginError::TokenError(e.to_string()))?;

    let refresh_token = jwt_config
        .generate_refresh_token(user.id, &user.email, &role_str)
        .map_err(|e| LoginError::TokenError(e.to_string()))?;

    // Store refresh token in database with extended expiry if remember_me is true
    store_refresh_token(
        &user.id,
        &refresh_token,
        jwt_config,
        &mut conn,
        login_data.remember_me.unwrap_or(false),
    )
    .await?;

    // Clean up old refresh tokens for this user
    cleanup_old_refresh_tokens(&user.id, &mut conn).await?;

    let response = LoginResponse {
        message: "Login successful".to_string(),
        user: UserInfo {
            id: user.id.to_string(),
            email: user.email,
            name: user.name,
            role: role_str,
            avatar: user.avatar,
            email_verified: user.email_verified,
        },
        access_token,
        refresh_token,
        expires_in: jwt_config.access_token_expiry.num_seconds(),
    };

    Ok(response)
}

async fn store_refresh_token(
    user_id: &uuid::Uuid,
    token: &str,
    jwt_config: &JwtConfig,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
    remember_me: bool,
) -> Result<(), LoginError> {
    // Hash the refresh token before storing
    let token_hash =
        PasswordService::hash_password(token).map_err(|e| LoginError::TokenError(e.to_string()))?;

    // Extend expiry time if remember_me is true (90 days instead of 30)
    let expiry_duration = if remember_me {
        chrono::Duration::days(90)
    } else {
        jwt_config.refresh_token_expiry
    };

    let new_refresh_token = NewRefreshToken {
        user_id: *user_id,
        token_hash: &token_hash,
        expires_at: Utc::now() + expiry_duration,
    };

    diesel::insert_into(refresh_tokens::table)
        .values(&new_refresh_token)
        .execute(conn)
        .map_err(|e| LoginError::DatabaseError(e.to_string()))?;

    Ok(())
}

async fn cleanup_old_refresh_tokens(
    user_id: &uuid::Uuid,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
) -> Result<(), LoginError> {
    // Delete expired tokens
    diesel::delete(
        refresh_tokens::table
            .filter(refresh_tokens::user_id.eq(user_id))
            .filter(refresh_tokens::expires_at.lt(Utc::now())),
    )
    .execute(conn)
    .map_err(|e| LoginError::DatabaseError(e.to_string()))?;

    // Keep only the 5 most recent tokens per user
    let tokens_to_keep: Vec<uuid::Uuid> = refresh_tokens::table
        .filter(refresh_tokens::user_id.eq(user_id))
        .filter(refresh_tokens::revoked.eq(false))
        .order(refresh_tokens::created_at.desc())
        .limit(5)
        .select(refresh_tokens::id)
        .load(conn)
        .map_err(|e| LoginError::DatabaseError(e.to_string()))?;

    if !tokens_to_keep.is_empty() {
        diesel::delete(
            refresh_tokens::table
                .filter(refresh_tokens::user_id.eq(user_id))
                .filter(refresh_tokens::id.ne_all(&tokens_to_keep)),
        )
        .execute(conn)
        .map_err(|e| LoginError::DatabaseError(e.to_string()))?;
    }

    Ok(())
}
