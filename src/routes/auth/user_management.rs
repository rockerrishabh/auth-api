use crate::{
    config::AppConfig,
    db::DbPool,
    error::AuthResult,
    middleware::extract_user_id_from_request,
    services::{email::EmailService, otp::OtpService, user::UserService},
};
use actix_web::{get, post, put, web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserEmailRequest {
    #[validate(email, length(max = 255))]
    pub new_email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserPhoneRequest {
    #[validate(length(min = 10, max = 20))]
    pub phone: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserNameRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserPasswordRequest {
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LockUserAccountRequest {
    #[validate(length(min = 36, max = 36))]
    pub user_id: String,
    pub locked: bool,
    #[validate(length(min = 1, max = 500))]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserManagementResponse {
    pub message: String,
    pub success: bool,
}

#[put("/email")]
pub async fn update_user_email(
    pool: web::Data<DbPool>,
    req: web::Json<UpdateUserEmailRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .update_user_email(current_user_id, &req.new_email)
        .await?;

    Ok(HttpResponse::Ok().json(UserManagementResponse {
        message: "Email updated successfully".to_string(),
        success: true,
    }))
}

#[put("/phone")]
pub async fn update_user_phone(
    pool: web::Data<DbPool>,
    req: web::Json<UpdateUserPhoneRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    if let Some(phone) = &req.phone {
        user_service
            .update_user_phone(current_user_id, phone)
            .await?;
    }

    Ok(HttpResponse::Ok().json(UserManagementResponse {
        message: "Phone number updated successfully".to_string(),
        success: true,
    }))
}

#[put("/name")]
pub async fn update_user_name(
    pool: web::Data<DbPool>,
    req: web::Json<UpdateUserNameRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .update_user_name(current_user_id, &req.name)
        .await?;

    Ok(HttpResponse::Ok().json(UserManagementResponse {
        message: "Name updated successfully".to_string(),
        success: true,
    }))
}

#[put("/password")]
pub async fn update_user_password(
    pool: web::Data<DbPool>,
    req: web::Json<UpdateUserPasswordRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .update_user_password(current_user_id, &req.new_password)
        .await?;

    // Clean up expired OTPs for the user after password change
    let otp_service = OtpService::new(
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

    // Don't fail the password update if OTP cleanup fails
    if let Err(e) = otp_service
        .cleanup_expired_otps_for_user(current_user_id)
        .await
    {
        eprintln!("Failed to cleanup OTPs after password update: {:?}", e);
    }

    Ok(HttpResponse::Ok().json(UserManagementResponse {
        message: "Password updated successfully".to_string(),
        success: true,
    }))
}

#[put("/avatar")]
pub async fn update_user_avatar(
    pool: web::Data<DbPool>,
    req: web::Json<serde_json::Value>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let avatar_path = req
        .get("avatar_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            crate::error::AuthError::ValidationFailed("avatar_path is required".to_string())
        })?;

    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .update_user_avatar(current_user_id, avatar_path)
        .await?;

    Ok(HttpResponse::Ok().json(UserManagementResponse {
        message: "Avatar updated successfully".to_string(),
        success: true,
    }))
}

#[post("/verification-status")]
pub async fn update_user_verification(
    pool: web::Data<DbPool>,
    req: web::Json<serde_json::Value>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    // Admin only endpoint
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

    let target_user_id = req
        .get("user_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            crate::error::AuthError::ValidationFailed("valid user_id is required".to_string())
        })?;

    let verified = req
        .get("verified")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| {
            crate::error::AuthError::ValidationFailed("verified boolean is required".to_string())
        })?;

    let email_verified_time = if verified { Some(Utc::now()) } else { None };
    user_service
        .update_user_verification(target_user_id, email_verified_time, None)
        .await?;

    Ok(HttpResponse::Ok().json(UserManagementResponse {
        message: format!("User verification status updated to {}", verified),
        success: true,
    }))
}

#[post("/lock-account")]
pub async fn lock_user_account(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<LockUserAccountRequest>,
    http_req: HttpRequest,
    geo_ip_service: Option<web::Data<Option<crate::services::geoip::GeoIPService>>>,
) -> AuthResult<HttpResponse> {
    // Admin only endpoint
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

    let target_user_id = Uuid::parse_str(&req.user_id).map_err(|_| {
        crate::error::AuthError::ValidationFailed("invalid user_id format".to_string())
    })?;

    // Explicitly access field to avoid dead code warning
    let locked_value = req.locked;
    let locked_until = if locked_value {
        Some(Utc::now() + chrono::Duration::hours(24)) // Lock for 24 hours
    } else {
        None
    };

    let updated_user = user_service
        .update_user_locked_status(target_user_id, locked_until)
        .await?;

    // Send notification email if account was locked
    if locked_value {
        let email_service = EmailService::new(config.email.clone());
        if let Ok(email_svc) = email_service {
            let reason = req.reason.as_deref().unwrap_or("Administrative action");
            let ip_address = crate::services::auth::extract_ip_address(&http_req);
            let user_agent = crate::services::auth::extract_user_agent(&http_req);

            let geo_ip_ref = geo_ip_service
                .as_ref()
                .and_then(|data| data.as_ref().as_ref());
            let result = email_svc
                .send_account_locked_email_with_details(
                    &updated_user.email,
                    &updated_user.username,
                    reason,
                    &ip_address,
                    &user_agent,
                    geo_ip_ref,
                )
                .await;
            if result.is_err() {
                eprintln!("Failed to send account locked email: {:?}", result.err());
            }
        }
    }

    Ok(HttpResponse::Ok().json(UserManagementResponse {
        message: format!(
            "User account {} successfully",
            if locked_value { "locked" } else { "unlocked" }
        ),
        success: true,
    }))
}

#[get("/statistics")]
pub async fn get_user_statistics(
    pool: web::Data<DbPool>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    // Admin only endpoint
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

    let total_users = user_service.get_total_user_count().await?;
    let active_users = user_service.get_active_user_count().await?;
    let verified_users = user_service.get_verified_user_count().await?;
    let users_with_2fa = user_service.get_users_with_2fa_count().await?;

    Ok(HttpResponse::Ok().json(json!({
        "total_users": total_users,
        "active_users": active_users,
        "verified_users": verified_users,
        "users_with_2fa": users_with_2fa,
        "success": true
    })))
}

/// Search users by term (uses the search_users service method)
#[get("/search/{search_term}")]
pub async fn search_users(
    pool: web::Data<DbPool>,
    search_term: web::Path<String>,
) -> AuthResult<HttpResponse> {
    let user_service = UserService::new(pool.get_ref().clone());
    let search_term_str = search_term.into_inner();

    // Use the search_users method to find users
    let users = user_service.search_users(&search_term_str).await?;

    Ok(HttpResponse::Ok().json(json!({
        "users": users,
        "search_term": search_term_str,
        "total_results": users.len(),
        "success": true
    })))
}
