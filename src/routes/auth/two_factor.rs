use crate::{
    config::AppConfig,
    db::DbPool,
    services::{
        core::{
            auth::{extract_ip_address, extract_user_agent},
            user::UserService,
        },
        utils::{
            email::EmailService,
            otp::{OtpRequest, OtpService, OtpVerificationRequest},
        },
    },
};
use actix_web::{post, web, HttpRequest, HttpResponse};
use validator::Validate;

#[derive(Debug, serde::Deserialize, Validate)]
pub struct EnableTwoFactorRequest {
    #[validate(length(min = 6, max = 6))]
    pub otp_code: String,
}

#[derive(Debug, serde::Deserialize, Validate)]
pub struct VerifyTwoFactorRequest {
    #[validate(length(min = 6, max = 6))]
    pub otp_code: String,
}

#[derive(Debug, serde::Deserialize, Validate)]
pub struct DisableTwoFactorRequest {
    #[validate(length(min = 6, max = 6))]
    pub otp_code: String,
}

#[derive(Debug, serde::Serialize)]
pub struct TwoFactorResponse {
    pub message: String,
    pub success: bool,
    pub two_factor_enabled: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct TwoFactorSetupResponse {
    pub message: String,
    pub success: bool,
    pub secret: String,
    pub qr_code_url: String,
}

/// Request to enable two-factor authentication
#[post("/enable")]
pub async fn enable_two_factor(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<EnableTwoFactorRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let otp_service = OtpService::new(config.security.clone(), pool.get_ref().clone());
    let email_service = EmailService::new(config.email.clone())?;

    // Get user details
    let user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Verify OTP code from database
    let verification_request = OtpVerificationRequest {
        user_id: user.id,
        otp_type: crate::db::models::OtpType::TwoFactor,
        code: req.otp_code.clone(),
    };
    let otp_verified = otp_service.verify_otp(&verification_request).await?;
    if !otp_verified {
        return Err(crate::error::AuthError::ValidationFailed(
            "Invalid OTP code".to_string(),
        ));
    }

    // Generate a new 2FA secret
    let secret = otp_service.generate_secure_otp(32);

    // Update user's 2FA status
    user_service
        .update_user_two_factor(user.id, true, Some(secret))
        .await?;

    // Send comprehensive 2FA confirmation email with device info
    let ip_address = extract_ip_address(&http_req);
    let user_agent = extract_user_agent(&http_req);

    email_service
        .send_two_factor_otp_email(
            &user.email,
            &user.username,
            &req.otp_code,
            10, // expiry minutes
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            &ip_address,
            "Unknown", // Could be enhanced with geo IP lookup
            &user_agent,
            "Unknown Browser", // Could be enhanced with user agent parsing
            &config.email.from_name,
        )
        .await?;

    Ok(HttpResponse::Ok().json(TwoFactorResponse {
        message: "Two-factor authentication enabled successfully".to_string(),
        success: true,
        two_factor_enabled: true,
    }))
}

/// Verify two-factor authentication code
#[post("/verify")]
pub async fn verify_two_factor(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<VerifyTwoFactorRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let otp_service = OtpService::new(config.security.clone(), pool.get_ref().clone());

    // Get user details
    let user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if !user.two_factor_enabled {
        return Err(crate::error::AuthError::ValidationFailed(
            "Two-factor authentication is not enabled".to_string(),
        ));
    }

    // Verify OTP code from database
    let verification_request = OtpVerificationRequest {
        user_id: user.id,
        otp_type: crate::db::models::OtpType::TwoFactor,
        code: req.otp_code.clone(),
    };
    let otp_verified = otp_service.verify_otp(&verification_request).await?;
    if !otp_verified {
        return Err(crate::error::AuthError::ValidationFailed(
            "Invalid OTP code".to_string(),
        ));
    }

    Ok(HttpResponse::Ok().json(TwoFactorResponse {
        message: "Two-factor authentication code verified successfully".to_string(),
        success: true,
        two_factor_enabled: true,
    }))
}

/// Disable two-factor authentication
#[post("/disable")]
pub async fn disable_two_factor(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<DisableTwoFactorRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let otp_service = OtpService::new(config.security.clone(), pool.get_ref().clone());
    let email_service = EmailService::new(config.email.clone())?;

    // Get user details
    let user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if !user.two_factor_enabled {
        return Err(crate::error::AuthError::ValidationFailed(
            "Two-factor authentication is not enabled".to_string(),
        ));
    }

    // Verify OTP code from database
    let verification_request = OtpVerificationRequest {
        user_id: user.id,
        otp_type: crate::db::models::OtpType::TwoFactor,
        code: req.otp_code.clone(),
    };
    let otp_verified = otp_service.verify_otp(&verification_request).await?;
    if !otp_verified {
        return Err(crate::error::AuthError::ValidationFailed(
            "Invalid OTP code".to_string(),
        ));
    }

    // Update user's 2FA status
    user_service
        .update_user_two_factor(user.id, false, None)
        .await?;

    // Send confirmation email
    email_service
        .send_security_alert_email(
            &user.email,
            &user.username,
            "2FA Disabled",
            "Two-factor authentication has been disabled for your account",
        )
        .await?;

    Ok(HttpResponse::Ok().json(TwoFactorResponse {
        message: "Two-factor authentication disabled successfully".to_string(),
        success: true,
        two_factor_enabled: false,
    }))
}

/// Send OTP for login verification when 2FA is enabled
#[post("/send-login-otp")]
pub async fn send_login_otp(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let otp_service = OtpService::new(config.security.clone(), pool.get_ref().clone());
    let email_service = EmailService::new(config.email.clone())?;

    // Get user details
    let user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if !user.two_factor_enabled {
        return Err(crate::error::AuthError::ValidationFailed(
            "Two-factor authentication is not enabled for this account".to_string(),
        ));
    }

    // Create and store OTP in database
    let otp_request = OtpRequest {
        user_id: user.id,
        otp_type: crate::db::models::OtpType::TwoFactor,
        email: Some(user.email.clone()),
        phone: None,
    };

    let otp_data = otp_service.store_otp(&otp_request).await?;
    let otp_code = otp_data.code.clone();

    // Extract request information for the email
    let ip_address = extract_ip_address(&http_req);
    let user_agent = extract_user_agent(&http_req);
    let login_time = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    // Send comprehensive 2FA login verification email
    email_service
        .send_two_factor_otp_email(
            &user.email,
            &user.username,
            &otp_code,
            10, // 10 minutes expiry
            &login_time,
            &ip_address,
            "Unknown", // Could be enhanced with geo IP lookup
            &user_agent,
            "Unknown Browser", // Could be enhanced with user agent parsing
            &config.email.from_name,
        )
        .await?;

    Ok(HttpResponse::Ok().json(TwoFactorResponse {
        message: "Two-factor authentication code sent to your email".to_string(),
        success: true,
        two_factor_enabled: true,
    }))
}

/// Get two-factor authentication setup information
#[post("/setup")]
pub async fn setup_two_factor(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let otp_service = OtpService::new(config.security.clone(), pool.get_ref().clone());

    // Get user details
    let user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if user.two_factor_enabled {
        return Err(crate::error::AuthError::ValidationFailed(
            "Two-factor authentication is already enabled".to_string(),
        ));
    }

    // Generate a new 2FA secret
    let secret = otp_service.generate_secure_otp(32);

    // Generate QR code URL for authenticator apps (simplified without urlencoding)
    let qr_code_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        config.email.from_name.replace(" ", "%20"),
        user.email.replace("@", "%40"),
        secret,
        config.email.from_name.replace(" ", "%20")
    );

    Ok(HttpResponse::Ok().json(TwoFactorSetupResponse {
        message: "Two-factor authentication setup initiated".to_string(),
        success: true,
        secret,
        qr_code_url,
    }))
}
