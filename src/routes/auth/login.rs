use actix_web::{cookie::Cookie, post, web, web::Data, HttpResponse, Result};
use chrono::{Duration, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use log::{error, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    config::AppConfig,
    db::{
        model::{NewRefreshToken, User},
        schema::{refresh_tokens, users},
        AppState,
    },
    utils::password::PasswordService,
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
    pub expires_in: i64,
}

#[derive(Serialize)]
pub struct UserInfo {
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

#[post("/login")]
pub async fn login_user(
    login_data: web::Json<LoginRequest>,
    pool: Data<AppState>,
    config: Data<AppConfig>,
) -> Result<HttpResponse> {
    info!("Login attempt for email: {}", login_data.email);

    match handle_login(login_data.into_inner(), &pool, &config).await {
        Ok((response, refresh_token, remember_me)) => {
            info!("Login successful for email: {}", response.user.email);

            // Create refresh token cookie
            let cookie = create_refresh_token_cookie(&refresh_token, &config, remember_me);

            Ok(HttpResponse::Ok().cookie(cookie).json(response))
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
    config: &AppConfig,
) -> Result<(LoginResponse, String, bool), LoginError> {
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

    let access_token = config
        .jwt
        .generate_access_token(user.id, &user.email)
        .map_err(|e| LoginError::TokenError(e.to_string()))?;

    let refresh_token = config
        .jwt
        .generate_refresh_token(user.id, &user.email)
        .map_err(|e| LoginError::TokenError(e.to_string()))?;

    // Store refresh token in database with extended expiry if remember_me is true
    store_refresh_token(
        &user.id,
        &refresh_token,
        config,
        &mut conn,
        login_data.remember_me.unwrap_or(false),
    )
    .await?;

    // Clean up old refresh tokens for this user
    cleanup_old_refresh_tokens(&user.id, &mut conn).await?;

    let remember_me = login_data.remember_me.unwrap_or(false);

    let response = LoginResponse {
        message: "Login successful".to_string(),
        user: UserInfo {
            id: user.id.to_string(),
            email: user.email,
            name: user.name,
            role: role_str,
            avatar: user.avatar,
            avatar_thumbnail: user.avatar_thumbnail,
            email_verified: user.email_verified,
            created_at: user.created_at.to_rfc3339(),
            updated_at: user.updated_at.map(|dt| dt.to_rfc3339()),
        },
        access_token,
        expires_in: config.jwt.access_token_expires_in,
    };

    Ok((response, refresh_token, remember_me))
}

async fn store_refresh_token(
    user_id: &uuid::Uuid,
    token: &str,
    config: &AppConfig,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
    remember_me: bool,
) -> Result<(), LoginError> {
    // Hash the refresh token before storing
    let token_hash =
        PasswordService::hash_password(token).map_err(|e| LoginError::TokenError(e.to_string()))?;

    // Extend expiry time if remember_me is true (90 days instead of default refresh token expiry)
    let expiry_duration = if remember_me {
        chrono::Duration::days(90)
    } else {
        chrono::Duration::seconds(config.jwt.refresh_token_expires_in)
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

    // Delete revoked tokens older than 7 days (keep recent ones for audit)
    let seven_days_ago = Utc::now() - Duration::days(7);
    diesel::delete(
        refresh_tokens::table
            .filter(refresh_tokens::user_id.eq(user_id))
            .filter(refresh_tokens::revoked.eq(true))
            .filter(refresh_tokens::created_at.lt(seven_days_ago)),
    )
    .execute(conn)
    .map_err(|e| LoginError::DatabaseError(e.to_string()))?;

    // Keep only the 5 most recent non-revoked tokens per user
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
                .filter(refresh_tokens::revoked.eq(false))
                .filter(refresh_tokens::id.ne_all(&tokens_to_keep)),
        )
        .execute(conn)
        .map_err(|e| LoginError::DatabaseError(e.to_string()))?;
    }

    Ok(())
}

fn create_refresh_token_cookie(
    refresh_token: &str,
    config: &AppConfig,
    remember_me: bool,
) -> Cookie<'static> {
    let max_age = if remember_me {
        // 90 days in seconds
        90 * 24 * 60 * 60
    } else {
        // Use configured refresh token expiry
        config.jwt.refresh_token_expires_in
    };

    Cookie::build("refresh_token", refresh_token.to_string())
        .domain(config.jwt.domain.clone())
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(max_age))
        .http_only(true)
        .secure(true) // Only send over HTTPS
        .same_site(actix_web::cookie::SameSite::Lax)
        .finish()
}
