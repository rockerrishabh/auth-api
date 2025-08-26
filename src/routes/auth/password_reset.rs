use crate::{
    config::AppConfig,
    db::DbPool,
    error::{AuthError, AuthResult},
    services::{
        activity::ActivityService, auth::extract_ip_address, email::EmailService, OtpService,
        PasswordService, UserService,
    },
};
use actix_web::{post, web, HttpRequest, HttpResponse};
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
    pub otp_code: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordResetResponse {
    pub message: String,
    pub success: bool,
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
    let otp_service = OtpService::new(config.security.clone(), pool.get_ref().clone());
    let email_service = EmailService::new(config.email.clone())?;

    // Check if user exists
    let user = user_service
        .get_user_by_email(&req.email)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Generate OTP for password reset
    let otp_code = otp_service.generate_otp(&crate::db::models::OtpType::PasswordReset);

    // Store OTP data in database
    let otp_request = crate::services::otp::OtpRequest {
        user_id: user.id,
        otp_type: crate::db::models::OtpType::PasswordReset,
        email: Some(req.email.clone()),
        phone: None,
    };

    // Store OTP in database and get the created OTP data
    let otp_data = otp_service.store_otp(&otp_request).await?;

    // Send OTP via email
    email_service
        .send_password_reset_email(
            &req.email,
            &user.username,
            &otp_code,
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
        description: "Password reset OTP sent to email".to_string(),
        ip_address: Some(ip_address),
        user_agent,
        metadata: Some(serde_json::json!({
            "email": req.email,
            "otp_id": otp_data.id
        })),
    };

    // Log activity (don't fail the request if logging fails)
    if let Err(activity_err) = activity_service.log_activity(activity_request).await {
        eprintln!("Failed to log password reset activity: {:?}", activity_err);
    }

    Ok(HttpResponse::Ok().json(PasswordResetResponse {
        message: "Password reset OTP sent to your email".to_string(),
        success: true,
    }))
}

/// Complete password reset with OTP
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
    let otp_service = OtpService::new(config.security.clone(), pool.get_ref().clone());

    // Check if user exists
    let user = user_service
        .get_user_by_email(&req.email)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    // Verify OTP from database
    let otp_verification_request = crate::services::otp::OtpVerificationRequest {
        user_id: user.id,
        otp_type: crate::db::models::OtpType::PasswordReset,
        code: req.otp_code.clone(),
    };

    let otp_verified = otp_service.verify_otp(&otp_verification_request).await?;

    if !otp_verified {
        return Err(AuthError::OtpInvalid);
    }

    // Validate password strength using the validate_password_reset method
    let password_reset_request = crate::services::password::PasswordResetRequest {
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

    // OTP is automatically marked as used during verification
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
    // 1. Clean up expired OTPs for this user
    let otp_service = crate::services::otp::OtpService::new(
        crate::config::SecurityConfig {
            argon2_memory_cost: 65536,
            argon2_time_cost: 3,
            argon2_parallelism: 1,
            lockout_duration: 900,
            max_failed_attempts: 5,
            session_timeout: 3600,
        },
        pool.get_ref().clone(),
    );

    // Clean up expired OTPs for this user
    match otp_service.cleanup_expired_otps_for_user(user_id).await {
        Ok(deleted_count) => {
            if deleted_count > 0 {
                println!(
                    "Cleaned up {} expired OTPs for user {}",
                    deleted_count, user_id
                );
            }
        }
        Err(e) => {
            eprintln!(
                "Failed to cleanup expired OTPs for user {}: {:?}",
                user_id, e
            );
        }
    }

    // 2. Log password reset activity
    let activity_service = crate::services::activity::ActivityService::new(pool.get_ref().clone());
    let activity_request = crate::services::activity::ActivityLogRequest {
        user_id,
        activity_type: "password_reset".to_string(),
        description: "Password was reset successfully".to_string(),
        ip_address: Some(crate::services::auth::extract_ip_address(&http_req)),
        user_agent: http_req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string()),
        metadata: Some(serde_json::json!({
            "reset_method": "otp",
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    };

    if let Err(e) = activity_service.log_activity(activity_request).await {
        eprintln!("Failed to log password reset activity: {:?}", e);
    }

    // 3. Send password reset confirmation email
    if let Some(config) = http_req.app_data::<web::Data<crate::config::AppConfig>>() {
        let email_service = crate::services::email::EmailService::new(config.email.clone());

        if let Ok(_) = email_service {
            // In a real implementation, you'd send a confirmation email here
            // For now, we just log the intent
            println!(
                "Password reset confirmation email would be sent to: {}",
                user_email
            );
        }
    }

    // 4. Revoke all existing sessions for security
    let session_service = crate::services::session::SessionService::new(pool.get_ref().clone());
    if let Err(e) = session_service.revoke_all_user_sessions(user_id).await {
        eprintln!(
            "Failed to revoke user sessions after password reset: {:?}",
            e
        );
    }

    Ok(())
}
