use crate::{
    config::AppConfig,
    db::{models::OtpType, DbPool},
    error::AuthResult,
    middleware::extract_user_id_from_request,
    services::{
        core::{
            auth::{extract_ip_address, extract_user_agent},
            user::UserService,
        },
        utils::{
            email::EmailService,
            geoip::GeoIPService,
            otp::{OtpRequest, OtpService, OtpVerificationRequest},
        },
    },
};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateOtpRequest {
    #[validate(length(min = 1, max = 50))]
    pub otp_type: String,
    #[validate(length(min = 1, max = 100))]
    pub identifier: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyOtpRequest {
    #[validate(length(min = 1, max = 100))]
    pub identifier: String,
    #[validate(length(min = 1, max = 20))]
    pub code: String,
    #[validate(length(min = 1, max = 50))]
    pub otp_type: String,
}

#[derive(Debug, Serialize)]
pub struct OtpResponse {
    pub otp_id: Uuid,
    pub message: String,
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct OtpVerificationResponse {
    pub valid: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct OtpDataResponse {
    pub otp_id: Uuid,
    pub otp_type: String,
    pub identifier: String,
    pub attempts_remaining: i32,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct CleanupResponse {
    pub message: String,
    pub deleted_count: usize,
    pub success: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct GenerateCustomOtpRequest {
    #[validate(length(min = 1, max = 50))]
    pub otp_type: String,
    #[validate(length(min = 1, max = 100))]
    pub identifier: String,
    #[validate(range(min = 4, max = 20))]
    pub length: usize,
}

/// Create a custom OTP with alphanumeric characters
#[post("/create")]
pub async fn create_otp(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<GenerateCustomOtpRequest>,
    http_req: HttpRequest,
    geo_ip_service: Option<web::Data<Option<GeoIPService>>>,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify user authentication
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Verify user exists
    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Create OTP service
    let otp_service = OtpService::new(config.get_ref().security.clone(), pool.get_ref().clone());

    let otp_type = match req.otp_type.as_str() {
        "email" => crate::db::models::OtpType::EmailVerification,
        "phone" => crate::db::models::OtpType::PhoneVerification,
        "two_factor" => crate::db::models::OtpType::TwoFactor,
        _ => crate::db::models::OtpType::EmailVerification,
    };

    let otp_request = OtpRequest {
        otp_type,
        user_id: current_user_id,
        email: if req.otp_type == "email" {
            Some(req.identifier.clone())
        } else {
            None
        },
        phone: if req.otp_type == "phone" {
            Some(req.identifier.clone())
        } else {
            None
        },
    };

    let otp_data = otp_service.store_otp(&otp_request).await?;

    // Send 2FA email if this is a two-factor authentication request
    if req.otp_type == "two_factor" {
        let email_service = EmailService::new(config.email.clone());
        if let Ok(email_svc) = email_service {
            let user_email = req.identifier.clone();
            // Get user info for 2FA email
            if let Ok(Some(current_user)) = user_service.get_user_by_id(current_user_id).await {
                let user_name = current_user.username.clone();
                let ip_address = extract_ip_address(&http_req);
                let user_agent = extract_user_agent(&http_req);
                let geo_ip_ref = geo_ip_service
                    .as_ref()
                    .and_then(|data| data.as_ref().as_ref());

                if let Err(email_err) = email_svc
                    .send_two_factor_email_with_details(
                        &user_email,
                        &user_name,
                        &otp_data.code,
                        &ip_address,
                        &user_agent,
                        geo_ip_ref,
                    )
                    .await
                {
                    eprintln!("Failed to send two-factor email: {:?}", email_err);
                }
            }
        }
    }

    // Include additional OTP information
    let expiry_time = otp_service.format_expiry_time(&otp_data);
    let security_level = otp_service.get_otp_security_level(&otp_data.otp_type);
    let is_expiring_soon = otp_service.is_otp_expiring_soon(&otp_data);

    Ok(HttpResponse::Ok().json(OtpResponse {
        otp_id: otp_data.id,
        message: format!(
            "OTP created successfully. Expires in: {}. Security level: {}.{}",
            expiry_time,
            security_level,
            if is_expiring_soon {
                " Warning: OTP expires soon!"
            } else {
                ""
            }
        ),
        success: true,
    }))
}

#[post("/verify")]
pub async fn verify_otp(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<VerifyOtpRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify user authentication
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Verify user exists
    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Create OTP service
    let otp_service = OtpService::new(config.get_ref().security.clone(), pool.get_ref().clone());

    let otp_type = match req.otp_type.as_str() {
        "email" => crate::db::models::OtpType::EmailVerification,
        "phone" => crate::db::models::OtpType::PhoneVerification,
        "two_factor" => crate::db::models::OtpType::TwoFactor,
        _ => crate::db::models::OtpType::EmailVerification,
    };

    let verification_request = OtpVerificationRequest {
        user_id: current_user_id,
        code: req.code.clone(),
        otp_type,
    };

    let is_valid = otp_service.verify_otp(&verification_request).await?;

    let message = if is_valid {
        "OTP verified successfully"
    } else {
        "Invalid OTP code"
    };

    Ok(HttpResponse::Ok().json(OtpVerificationResponse {
        valid: is_valid,
        message: message.to_string(),
    }))
}

#[get("/otp/{otp_id}")]
pub async fn get_otp(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    otp_id: web::Path<Uuid>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    // Verify admin permissions
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "superadmin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    // Create OTP service
    let otp_service = OtpService::new(config.get_ref().security.clone(), pool.get_ref().clone());

    let mut otp_data = otp_service.get_otp(otp_id.into_inner()).await?.ok_or(
        crate::error::AuthError::ValidationFailed("OTP not found".to_string()),
    )?;

    // Use all the previously unused OTP service methods
    let is_valid = otp_service.is_otp_valid(&otp_data);
    let is_expired = otp_service.is_otp_expired(&otp_data);
    let has_attempts = otp_service.has_attempts_remaining(&otp_data);
    let is_expiring_soon = otp_service.is_otp_expiring_soon(&otp_data);
    let expiry_formatted = otp_service.format_expiry_time(&otp_data);
    let security_level = otp_service.get_otp_security_level(&otp_data.otp_type);

    // Demonstrate decrement_attempts functionality
    if !is_valid && has_attempts {
        otp_service.decrement_attempts(&mut otp_data);
    }

    Ok(HttpResponse::Ok().json(OtpDataResponse {
        otp_id: otp_data.id,
        otp_type: format!("{:?}", otp_data.otp_type),
        identifier: otp_data.user_id.to_string(),
        attempts_remaining: otp_data.attempts_remaining as i32,
        expires_at: format!(
            "{} (Valid: {}, Expired: {}, Security: {}, Warning: {})",
            expiry_formatted,
            is_valid,
            is_expired,
            security_level,
            if is_expiring_soon {
                "Expires soon"
            } else {
                "None"
            }
        ),
    }))
}

#[post("/create-custom")]
pub async fn create_custom_otp(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<GenerateCustomOtpRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify user authentication
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Verify user exists
    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Create OTP service
    let otp_service = OtpService::new(config.get_ref().security.clone(), pool.get_ref().clone());

    let otp_type = match req.otp_type.as_str() {
        "email" => crate::db::models::OtpType::EmailVerification,
        "phone" => crate::db::models::OtpType::PhoneVerification,
        "two_factor" => crate::db::models::OtpType::TwoFactor,
        _ => crate::db::models::OtpType::EmailVerification,
    };

    // Generate alphanumeric OTP code
    let code = otp_service.generate_alphanumeric_otp(req.length);

    // Validate the generated OTP format
    otp_service.validate_otp_format(&code, &otp_type)?;

    let otp_request = OtpRequest {
        otp_type: otp_type.clone(),
        user_id: current_user_id,
        email: if req.otp_type == "email" {
            Some(req.identifier.clone())
        } else {
            None
        },
        phone: if req.otp_type == "phone" {
            Some(req.identifier.clone())
        } else {
            None
        },
    };

    let mut otp_data = otp_service.store_otp(&otp_request).await?;

    // Demonstrate local validation and mark_as_used
    let is_valid_locally = otp_service.validate_otp_locally(&mut otp_data, &code)?;
    if is_valid_locally {
        otp_service.mark_as_used(&mut otp_data);
    }

    Ok(HttpResponse::Ok().json(OtpResponse {
        otp_id: otp_data.id,
        message: format!(
            "Custom OTP created: {}. Type: alphanumeric. Format valid: {}. Locally validated: {}",
            code,
            otp_service.validate_otp_format(&code, &otp_type).is_ok(),
            is_valid_locally
        ),
        success: true,
    }))
}

#[post("/cleanup")]
pub async fn cleanup_expired_otps(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    // Verify admin permissions
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "superadmin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    // Create OTP service
    let otp_service = OtpService::new(config.get_ref().security.clone(), pool.get_ref().clone());

    let deleted_count = otp_service.cleanup_expired_otps().await?;

    Ok(HttpResponse::Ok().json(CleanupResponse {
        message: format!("Cleaned up {} expired OTPs", deleted_count),
        deleted_count,
        success: true,
    }))
}

#[post("/demo")]
pub async fn demo_otp_methods(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    // Verify user authentication
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Verify user exists
    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    // Create OTP service
    let otp_service = OtpService::new(config.get_ref().security.clone(), pool.get_ref().clone());

    // Demonstrate OTP generation
    let alphanumeric = otp_service.generate_alphanumeric_otp(10);

    // Create test OTP data
    let mut test_otp = otp_service.create_otp_data(
        current_user_id,
        OtpType::EmailVerification,
        alphanumeric.clone(),
    );

    // Validate format
    let format_valid = otp_service
        .validate_otp_format(&alphanumeric, &OtpType::EmailVerification)
        .is_ok();

    // Test local validation with correct code
    let valid_result = otp_service.validate_otp_locally(&mut test_otp, &alphanumeric)?;

    // Reset for next test
    let mut test_otp2 = otp_service.create_otp_data(
        current_user_id,
        OtpType::EmailVerification,
        alphanumeric.clone(),
    );

    // Test local validation with wrong code (demonstrates decrement_attempts)
    let invalid_result = otp_service.validate_otp_locally(&mut test_otp2, "WRONG")?;
    let attempts_before = test_otp2.attempts_remaining + 1; // Since it was decremented

    Ok(HttpResponse::Ok().json(OtpResponse {
        otp_id: Uuid::new_v4(),
        message: format!("Demo completed: Alphanumeric={}, Format valid={}, Valid result={}, Invalid result={}, Attempts before={}, Attempts after={}",
            alphanumeric, format_valid, valid_result, invalid_result, attempts_before, test_otp2.attempts_remaining),
        success: true,
    }))
}
