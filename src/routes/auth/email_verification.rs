use crate::{
    config::AppConfig,
    db::DbPool,
    error::AuthError,
    services::{jwt::JwtService, UserService},
};
use actix_web::{get, web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct SendVerificationRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 6, max = 6))]
    pub otp_code: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailLinkRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct EmailVerificationResponse {
    pub message: String,
    pub success: bool,
    pub email_verified: bool,
}

/// Verify email using JWT token from registration link
#[get("/verify")]
pub async fn verify_email_link(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Query<VerifyEmailLinkRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, AuthError> {
    let jwt_service = JwtService::new(config.jwt.clone())?;

    // Verify the JWT token
    let claims = jwt_service.verify_access_token(&req.token)?;

    // Check if token is for unverified user
    if claims.token_type != "access" || claims.role != "unverified" {
        return Err(AuthError::InvalidToken);
    }

    let user_service = UserService::new(pool.get_ref().clone());

    // Get the user
    let user = user_service
        .get_user_by_id(claims.sub.parse::<uuid::Uuid>()?)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    // Check if already verified
    if user.email_verified_at.is_some() {
        return Ok(HttpResponse::Ok().json(EmailVerificationResponse {
            message: "Email already verified".to_string(),
            success: true,
            email_verified: true,
        }));
    }

    // Verify the email
    user_service
        .update_user_verification(user.id, Some(Utc::now()), None)
        .await?;

    // Log the verification activity
    let activity_service = crate::services::activity::ActivityService::new(pool.get_ref().clone());
    let activity_request = crate::services::activity::ActivityLogRequest {
        user_id: user.id,
        activity_type: "email_verification".to_string(),
        description: "Email verified via registration link".to_string(),
        ip_address: Some(crate::services::auth::extract_ip_address(&http_req)),
        user_agent: http_req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string()),
        metadata: Some(serde_json::json!({
            "verification_method": "jwt_link"
        })),
    };

    // Don't fail if activity logging fails
    if let Err(e) = activity_service.log_activity(activity_request).await {
        eprintln!("Failed to log email verification activity: {:?}", e);
    }

    Ok(HttpResponse::Ok().json(EmailVerificationResponse {
        message: "Email verified successfully".to_string(),
        success: true,
        email_verified: true,
    }))
}
