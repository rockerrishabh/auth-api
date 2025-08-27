use crate::config::AppConfig;
use crate::db::DbPool;
use crate::services::core::user::UserResponse;
use crate::services::{
    activity::ActivityService,
    core::auth::{AuthService, LoginRequest},
    core::session::SessionService,
    core::user::UserService,
    utils::jwt::JwtService,
};
use actix_web::{post, web, HttpRequest, HttpResponse};
use serde::Serialize;
use validator::Validate;

#[derive(Debug, Serialize)]
pub struct SecureLoginResponse {
    pub message: String,
    pub user: UserResponse,
    pub access_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct TwoFactorRequiredResponse {
    pub message: String,
    pub user: UserResponse,
    pub two_factor_required: bool,
    pub otp_sent: bool,
}

#[post("/login")]
pub async fn login_user(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<LoginRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Create services
    let jwt_service = JwtService::new(config.jwt.clone())?;
    let session_service = SessionService::new(pool.get_ref().clone());
    let activity_service = ActivityService::new(pool.get_ref().clone());
    let user_service = UserService::new(pool.get_ref().clone());
    let auth_service = AuthService::new(
        pool.get_ref().clone(),
        jwt_service.clone(),
        session_service.clone(),
        activity_service.clone(),
        user_service,
        config.get_ref().clone(),
    );

    let response = auth_service.login(req.into_inner(), &http_req).await?;

    // Check if 2FA is required (indicated by empty access token)
    if response.access_token.is_empty() {
        // 2FA is required, return 2FA response
        let two_factor_response = TwoFactorRequiredResponse {
            message: response.message,
            user: response.user,
            two_factor_required: true,
            otp_sent: true,
        };

        return Ok(HttpResponse::Ok().json(two_factor_response));
    }

    // Normal login successful, create secure HTTP-only cookie for refresh token
    let refresh_token_cookie =
        actix_web::cookie::Cookie::build("refresh_token", response.session_token)
            .http_only(true)
            .secure(config.is_production()) // Only HTTPS in production
            .same_site(actix_web::cookie::SameSite::Lax)
            .path("/v1/auth")
            .max_age(actix_web::cookie::time::Duration::hours(24 * 7)) // 7 days
            .finish();

    let secure_response = SecureLoginResponse {
        message: response.message,
        user: response.user,
        access_token: response.access_token,
        expires_in: response.expires_in,
    };

    Ok(HttpResponse::Ok()
        .cookie(refresh_token_cookie)
        .json(secure_response))
}
