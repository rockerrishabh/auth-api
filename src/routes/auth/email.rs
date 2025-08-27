use crate::{
    config::AppConfig,
    db::DbPool,
    error::AuthResult,
    middleware::extract_user_id_from_request,
    services::{
        core::{
            auth::{extract_ip_address, extract_user_agent},
            user::UserService,
        },
        utils::{
            email::{EmailRequest, EmailService},
            geoip::GeoIPService,
            otp::OtpService,
        },
    },
};
use actix_web::{post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct SendEmailRequest {
    #[validate(email, length(max = 255))]
    pub to: String,
    #[validate(length(min = 1, max = 255))]
    pub subject: String,
    #[validate(length(min = 1))]
    pub body: String,
    #[validate(length(max = 10000))]
    pub html_body: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SendWelcomeEmailRequest {
    #[validate(email, length(max = 255))]
    pub to: String,
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(email, length(max = 255))]
    pub email: String,
    #[validate(length(min = 1, max = 50))]
    pub username: String,
    #[validate(length(min = 1, max = 20))]
    pub account_status: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SendSecurityAlertEmailRequest {
    #[validate(email, length(max = 255))]
    pub to: String,
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(length(min = 1, max = 100))]
    pub alert_type: String,
    #[validate(length(min = 1))]
    pub details: String,
}

#[derive(Debug, Serialize)]
pub struct EmailResponse {
    pub message: String,
    pub success: bool,
}

#[post("/send")]
pub async fn send_email(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<SendEmailRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    // Create email service
    let email_service = EmailService::new(config.get_ref().email.clone())?;

    let email_request = EmailRequest {
        to: req.to.clone(),
        subject: req.subject.clone(),
        body: req.body.clone(),
        html_body: req.html_body.clone(),
    };

    email_service.send_email(email_request).await?;

    Ok(HttpResponse::Ok().json(EmailResponse {
        message: "Email sent successfully".to_string(),
        success: true,
    }))
}

#[post("/welcome")]
pub async fn send_welcome_email(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<SendWelcomeEmailRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    // Create email service
    let email_service = EmailService::new(config.get_ref().email.clone())?;

    let created_at = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let account_status = req.account_status.as_deref().unwrap_or("Active");

    email_service
        .send_welcome_email(
            &req.to,
            &req.name,
            &req.email,
            &req.username,
            account_status,
            &created_at,
        )
        .await?;

    Ok(HttpResponse::Ok().json(EmailResponse {
        message: "Welcome email sent successfully".to_string(),
        success: true,
    }))
}

#[post("/security-alert")]
pub async fn send_security_alert_email(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<SendSecurityAlertEmailRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    // Create email service
    let email_service = EmailService::new(config.get_ref().email.clone())?;

    // Extract real client information
    let ip_address = extract_ip_address(&http_req);
    let user_agent = extract_user_agent(&http_req);

    email_service
        .send_security_alert_email_with_details(
            &req.to,
            &req.name,
            &req.alert_type,
            &req.details,
            &ip_address,
            &user_agent,
        )
        .await?;

    Ok(HttpResponse::Ok().json(EmailResponse {
        message: "Security alert email sent successfully".to_string(),
        success: true,
    }))
}

#[post("/test-otp")]
pub async fn test_otp_email(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<SendWelcomeEmailRequest>,
    http_req: HttpRequest,
    geo_ip_service: Option<web::Data<Option<GeoIPService>>>,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let _current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if _current_user.role != "admin" && _current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    // Create email service
    let email_service = EmailService::new(config.get_ref().email.clone())?;

    // Extract real client information
    let ip_address = extract_ip_address(&http_req);
    let user_agent = extract_user_agent(&http_req);
    let geo_ip_ref = geo_ip_service
        .as_ref()
        .and_then(|data| data.as_ref().as_ref());

    // Generate a test OTP
    let otp_service = OtpService::new(config.get_ref().security.clone(), pool.get_ref().clone());
    let test_otp = otp_service.generate_otp(&crate::db::models::OtpType::EmailVerification);

    email_service
        .send_otp_email_with_details(
            &req.to,
            &req.name,
            &test_otp,
            5, // 5 minutes for testing
            &ip_address,
            &user_agent,
            geo_ip_ref,
        )
        .await?;

    Ok(HttpResponse::Ok().json(EmailResponse {
        message: format!(
            "Test OTP email sent successfully to {} with code: {}",
            req.to, test_otp
        ),
        success: true,
    }))
}
