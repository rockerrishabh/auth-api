use crate::{
    config::AppConfig,
    db::DbPool,
    error::{AuthError, AuthResult},
    services::{
        activity::ActivityService,
        core::{
            auth::extract_ip_address, password::PasswordResetRequest, password::PasswordService,
            session::SessionService, user::UserService,
        },
        utils::{email::EmailService, jwt::JwtService},
    },
};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct RequestPasswordResetRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CompletePasswordResetRequest {
    #[validate(length(min = 8))]
    pub new_password: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordResetResponse {
    pub message: String,
    pub success: bool,
}

#[derive(Debug, Deserialize)]
pub struct VerifyPasswordResetRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyPasswordResetResponse {
    pub valid: bool,
    pub email: Option<String>,
    pub message: String,
}

/// Request a password reset
#[post("/request")]
pub async fn request_password_reset(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<RequestPasswordResetRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_service = UserService::new(pool.get_ref().clone());
    let jwt_service = JwtService::new(config.jwt.clone())?;
    let email_service = EmailService::new(config.email.clone())?;

    // Check if user exists
    let user = user_service
        .get_user_by_email(&req.email)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Generate JWT token for password reset
    let reset_token = jwt_service.generate_password_reset_token(user.id, &req.email)?;

    // Create reset URL using configured frontend URL
    let reset_url = format!(
        "{}/auth/reset-password?token={}",
        config.frontend_url, reset_token
    );

    // Send password reset email with clickable link
    email_service
        .send_password_reset_email_with_link(
            &req.email,
            &user.username,
            &reset_url,
            15, // 15 minutes expiry
        )
        .await?;

    // Log the password reset request activity
    let activity_service = ActivityService::new(pool.get_ref().clone());
    let ip_address = extract_ip_address(&http_req);
    let user_agent = http_req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let activity_request = crate::services::activity::ActivityLogRequest {
        user_id: user.id,
        activity_type: "password_reset_request".to_string(),
        description: "Password reset link sent to email".to_string(),
        ip_address: Some(ip_address),
        user_agent,
        metadata: Some(serde_json::json!({
            "email": req.email,
            "reset_method": "jwt_link"
        })),
    };

    // Log activity (don't fail the request if logging fails)
    if let Err(activity_err) = activity_service.log_activity(activity_request).await {
        eprintln!("Failed to log password reset activity: {:?}", activity_err);
    }

    Ok(HttpResponse::Ok().json(PasswordResetResponse {
        message: "Password reset link sent to your email".to_string(),
        success: true,
    }))
}

/// Verify password reset token
#[get("/verify")]
pub async fn verify_password_reset_token(
    config: web::Data<AppConfig>,
    req: web::Query<VerifyPasswordResetRequest>,
) -> Result<HttpResponse, crate::error::AuthError> {
    let jwt_service = JwtService::new(config.jwt.clone())?;

    match jwt_service.verify_password_reset_token(&req.token) {
        Ok(claims) => Ok(HttpResponse::Ok().json(VerifyPasswordResetResponse {
            valid: true,
            email: Some(claims.email),
            message: "Token is valid".to_string(),
        })),
        Err(AuthError::TokenExpired) => Ok(HttpResponse::Ok().json(VerifyPasswordResetResponse {
            valid: false,
            email: None,
            message: "Token has expired".to_string(),
        })),
        Err(AuthError::InvalidToken) => Ok(HttpResponse::Ok().json(VerifyPasswordResetResponse {
            valid: false,
            email: None,
            message: "Invalid token".to_string(),
        })),
        Err(e) => Err(e),
    }
}

/// Complete password reset with JWT token
#[post("/complete")]
pub async fn complete_password_reset(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<CompletePasswordResetRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_service = UserService::new(pool.get_ref().clone());
    let password_service = PasswordService::new(config.get_ref().clone());
    let jwt_service = JwtService::new(config.jwt.clone())?;

    // Verify JWT token
    let claims = jwt_service.verify_password_reset_token(&req.token)?;

    // Get user ID from token claims
    let user_id = claims
        .sub
        .parse::<uuid::Uuid>()
        .map_err(|e| AuthError::ValidationFailed(format!("Invalid user ID in token: {}", e)))?;

    // Check if user exists
    let user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    // Validate password strength using the validate_password_reset method
    let password_reset_request = PasswordResetRequest {
        new_password: req.new_password.clone(),
        confirm_password: req.new_password.clone(), // Use same password for confirmation
    };
    password_service.validate_password_reset(&password_reset_request)?;

    // Hash the new password
    let hashed_password = password_service.hash_password(&req.new_password)?;

    // Update user's password
    user_service
        .update_user_password(user.id, &hashed_password)
        .await?;

    // JWT token is automatically verified and expired
    // Perform additional security cleanup after password reset
    perform_password_reset_cleanup(user.id, &user.email, pool, http_req).await?;

    Ok(HttpResponse::Ok().json(PasswordResetResponse {
        message: "Password successfully reset".to_string(),
        success: true,
    }))
}

/// Perform additional cleanup after password reset
async fn perform_password_reset_cleanup(
    user_id: uuid::Uuid,
    user_email: &str,
    pool: web::Data<DbPool>,
    http_req: HttpRequest,
) -> AuthResult<()> {
    // Log password reset activity
    let activity_service = crate::services::activity::ActivityService::new(pool.get_ref().clone());
    let activity_request = crate::services::activity::ActivityLogRequest {
        user_id,
        activity_type: "password_reset".to_string(),
        description: "Password was reset successfully".to_string(),
        ip_address: Some(extract_ip_address(&http_req)),
        user_agent: http_req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string()),
        metadata: Some(serde_json::json!({
            "reset_method": "jwt_link",
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    };

    if let Err(e) = activity_service.log_activity(activity_request).await {
        eprintln!("Failed to log password reset activity: {:?}", e);
    }

    // Send password reset confirmation email
    if let Some(config) = http_req.app_data::<web::Data<crate::config::AppConfig>>() {
        let email_service = EmailService::new(config.email.clone());

        if let Ok(_) = email_service {
            // In a real implementation, you'd send a confirmation email here
            // For now, we just log the intent
            println!(
                "Password reset confirmation email would be sent to: {}",
                user_email
            );
        }
    }

    // Revoke all existing sessions for security
    let session_service = SessionService::new(pool.get_ref().clone());
    if let Err(e) = session_service.revoke_all_user_sessions(user_id).await {
        eprintln!(
            "Failed to revoke user sessions after password reset: {:?}",
            e
        );
    }

    Ok(())
}
