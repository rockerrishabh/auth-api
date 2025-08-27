use crate::config::AppConfig;
use crate::services::utils::jwt::JwtService;
use actix_web::{post, web, HttpRequest, HttpResponse};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SecureRefreshTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

#[post("/refresh")]
pub async fn refresh_token(
    config: web::Data<AppConfig>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Extract refresh token from HTTP-only cookie
    let cookies = http_req
        .cookies()
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let refresh_token = cookies
        .iter()
        .find(|cookie| cookie.name() == "refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or(crate::error::AuthError::InvalidToken)?;

    // Extract user_id from the refresh token using JWT utility method
    let jwt_service = JwtService::new(config.jwt.clone())?;

    // Use JWT utility method to extract user_id from token
    let user_id = jwt_service.extract_user_id_from_token(&refresh_token, "refresh")?;

    // Get claims for email and role (needed for new token generation)
    let claims = jwt_service.verify_refresh_token(&refresh_token)?;

    // Generate new access token (don't regenerate refresh token for security)
    let new_access_token =
        jwt_service.generate_access_token(user_id, &claims.email, &claims.role)?;

    let response = SecureRefreshTokenResponse {
        access_token: new_access_token,
        token_type: "Bearer".to_string(),
        expires_in: config.jwt.access_token_expiry,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[derive(Debug, serde::Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Refresh access token using the dedicated method (uses refresh_access_token)
#[post("/refresh-token")]
pub async fn refresh_token_dedicated(
    config: web::Data<AppConfig>,
    req: web::Json<RefreshTokenRequest>,
) -> Result<HttpResponse, crate::error::AuthError> {
    let jwt_service = JwtService::new(config.jwt.clone())?;

    // Use the dedicated refresh_access_token method (uses the unused method)
    let new_access_token = jwt_service.refresh_access_token(&req.refresh_token)?;

    let response = SecureRefreshTokenResponse {
        access_token: new_access_token,
        token_type: "Bearer".to_string(),
        expires_in: config.jwt.access_token_expiry,
    };

    Ok(HttpResponse::Ok().json(response))
}
