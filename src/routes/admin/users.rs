use crate::{
    db::DbPool,
    services::core::{user::UserResponse, user::UserService},
};
use actix_web::{get, post, put, web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct UserSearchRequest {
    #[validate(length(max = 100))]
    pub query: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    pub email_verified: Option<bool>,
    pub two_factor_enabled: Option<bool>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserSearchResponse {
    pub users: Vec<UserResponse>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub total_pages: i64,
    pub filters_applied: Vec<(String, String)>,
    pub sort_by: String,
    pub sort_order: String,
}

#[derive(Debug, Serialize)]
pub struct BulkUpdateResponse {
    pub message: String,
    pub success: bool,
    pub updated_count: i64,
    pub failed_updates: Vec<String>,
    pub update_details: Vec<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct BulkUpdateUsersRequest {
    #[validate(length(min = 1))]
    pub user_ids: Vec<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    pub email_verified: Option<bool>,
    pub two_factor_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminUpdateUserEmailRequest {
    #[validate(email(message = "Invalid email format"))]
    pub new_email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminUpdateUserPhoneRequest {
    #[validate(length(
        min = 10,
        max = 15,
        message = "Phone number must be between 10 and 15 characters"
    ))]
    pub phone: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminUpdateUserNameRequest {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Name must be between 2 and 100 characters"
    ))]
    pub name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminUpdateUserAvatarRequest {
    #[validate(length(min = 1, message = "Avatar path is required"))]
    pub avatar_path: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminUpdateUserVerificationRequest {
    pub email_verified: bool,
    pub phone_verified: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminLockUserAccountRequest {
    pub lock_until: Option<String>, // ISO date string
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminUnlockUserAccountRequest {
    pub reason: Option<String>,
}

/// Search and filter users with advanced options
#[post("/search")]
pub async fn search_users(
    pool: web::Data<DbPool>,
    req: web::Json<UserSearchRequest>,
    _http_req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_service = UserService::new(pool.get_ref().clone());

    // Extract search parameters
    let page = req.page.unwrap_or(1);
    let per_page = req.per_page.unwrap_or(10);
    let role_filter = req.role.as_deref();
    let status_filter = req.status.as_deref();
    let email_verified = req.email_verified;
    let two_factor_enabled = req.two_factor_enabled;
    let sort_by = req.sort_by.as_deref().unwrap_or("created_at");
    let sort_order = req.sort_order.as_deref().unwrap_or("desc");

    // Use the advanced user search service method
    let (users_list, total) = user_service
        .advanced_user_search(
            req.query.as_deref(), // Fixed: Use query instead of search_term
            role_filter,
            status_filter,
            email_verified,
            two_factor_enabled,
            page as i64,
            per_page as i64,
            sort_by,
            sort_order,
        )
        .await?;

    // Create response with users from service
    let total_pages = (total + per_page - 1) / per_page;
    let filters_applied = vec![
        ("role".to_string(), req.role.clone().unwrap_or_default()),
        ("status".to_string(), req.status.clone().unwrap_or_default()),
        (
            "email_verified".to_string(),
            req.email_verified
                .map(|v| v.to_string())
                .unwrap_or_default(),
        ),
        (
            "two_factor_enabled".to_string(),
            req.two_factor_enabled
                .map(|v| v.to_string())
                .unwrap_or_default(),
        ),
    ]
    .into_iter()
    .filter(|(_, v)| !v.is_empty())
    .collect();

    let response = UserSearchResponse {
        users: users_list,
        total,
        page,
        per_page,
        total_pages,
        filters_applied,
        sort_by: sort_by.to_string(),
        sort_order: sort_order.to_string(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Bulk update users
#[post("/bulk-update")]
pub async fn bulk_update_users(
    pool: web::Data<DbPool>,
    req: web::Json<BulkUpdateUsersRequest>,
    _http_req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_service = UserService::new(pool.get_ref().clone());

    let mut updated_count = 0;
    let mut failed_updates = Vec::new();
    let mut update_details = Vec::new();

    for user_id in &req.user_ids {
        let mut user_updated = false;

        // Update role if provided
        if let Some(role_str) = &req.role {
            match user_service
                .update_user_role(user_id.parse()?, role_str)
                .await
            {
                Ok(_) => {
                    user_updated = true;
                    update_details.push(format!("Role updated to {}", role_str));
                }
                Err(e) => {
                    failed_updates.push((user_id.clone(), format!("Role update failed: {}", e)));
                    continue;
                }
            }
        }

        // Update status if provided
        if let Some(status_str) = &req.status {
            match user_service
                .update_user_status(user_id.parse()?, status_str)
                .await
            {
                Ok(_) => {
                    user_updated = true;
                    update_details.push(format!("Status updated to {}", status_str));
                }
                Err(e) => {
                    failed_updates.push((user_id.clone(), format!("Status update failed: {}", e)));
                    continue;
                }
            }
        }

        // Update email verification if provided
        if let Some(verified) = req.email_verified {
            let verification_time = if verified { Some(Utc::now()) } else { None };
            match user_service
                .update_user_verification(user_id.parse()?, verification_time, None)
                .await
            {
                Ok(_) => {
                    user_updated = true;
                    update_details.push(format!("Email verification set to {}", verified));
                }
                Err(e) => {
                    failed_updates.push((
                        user_id.clone(),
                        format!("Email verification update failed: {}", e),
                    ));
                    continue;
                }
            }
        }

        // Update 2FA status if provided
        if let Some(enabled) = req.two_factor_enabled {
            let secret = if enabled {
                Some("2fa_secret_generated".to_string())
            } else {
                None
            };
            match user_service
                .update_user_two_factor(user_id.parse()?, enabled, secret)
                .await
            {
                Ok(_) => {
                    user_updated = true;
                    update_details.push(format!("2FA status set to {}", enabled));
                }
                Err(e) => {
                    failed_updates.push((user_id.clone(), format!("2FA update failed: {}", e)));
                    continue;
                }
            }
        }

        if user_updated {
            updated_count += 1;
        }
    }

    let response = BulkUpdateResponse {
        message: format!(
            "Bulk update completed. {} users updated, {} failed",
            updated_count,
            failed_updates.len()
        ),
        success: true,
        updated_count,
        failed_updates: failed_updates
            .into_iter()
            .map(|(id, reason)| format!("User {}: {}", id, reason))
            .collect(),
        update_details,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get user statistics for admin dashboard
#[get("/statistics")]
pub async fn get_user_statistics(
    pool: web::Data<DbPool>,
    _http_req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_service = UserService::new(pool.get_ref().clone());

    // Get basic statistics using available methods
    let total_users = user_service.get_total_user_count().await?;
    let active_users = user_service.get_active_user_count().await?;
    let verified_users = user_service.get_verified_user_count().await?;
    let two_fa_users = user_service.get_users_with_2fa_count().await?;
    let recent_users = user_service.get_recent_registrations_count(7).await?;

    let stats = serde_json::json!({
        "total_users": total_users,
        "active_users": active_users,
        "verified_users": verified_users,
        "two_factor_users": two_fa_users,
        "recent_registrations": recent_users,
        "timestamp": Utc::now().to_rfc3339()
    });

    Ok(HttpResponse::Ok().json(stats))
}

/// Search user by username
#[get("/search/username/{username}")]
pub async fn search_user_by_username(
    pool: web::Data<DbPool>,
    username: web::Path<String>,
    _http_req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_service = UserService::new(pool.get_ref().clone());

    let username_str = username.into_inner();

    match user_service.get_user_by_username(&username_str).await? {
        Some(user) => Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "user": user,
            "search_term": username_str
        }))),
        None => Ok(HttpResponse::NotFound().json(json!({
            "success": false,
            "message": format!("User with username '{}' not found", username_str),
            "search_term": username_str
        }))),
    }
}

/// Get user preferences
#[get("/{user_id}/preferences")]
pub async fn get_user_preferences(
    pool: web::Data<DbPool>,
    user_id: web::Path<uuid::Uuid>,
    _http_req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_service = UserService::new(pool.get_ref().clone());

    let user = user_service
        .get_user_by_id(user_id.into_inner())
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "user_id": user.id,
        "preferences": user.preferences,
        "username": user.username,
        "email": user.email
    })))
}

/// Export users as CSV
#[get("/export")]
pub async fn export_users(
    pool: web::Data<DbPool>,
    _http_req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_service = UserService::new(pool.get_ref().clone());

    let csv_data = user_service.export_users_csv(false).await?;
    Ok(HttpResponse::Ok()
        .content_type("text/csv")
        .append_header(("Content-Disposition", "attachment; filename=users.csv"))
        .body(csv_data))
}

/// Update user preferences
#[put("/{user_id}/preferences")]
pub async fn update_user_preferences(
    pool: web::Data<DbPool>,
    user_id: web::Path<uuid::Uuid>,
    req: web::Json<serde_json::Value>,
    _http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_service = UserService::new(pool.get_ref().clone());
    let user_id_value = user_id.into_inner();

    // Update user preferences
    let updated_user = user_service
        .update_user_preferences(user_id_value, req.0.clone())
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "message": "User preferences updated successfully",
        "user_id": user_id_value,
        "preferences": updated_user.preferences
    })))
}

/// Admin endpoint to update user email
#[put("/{user_id}/email")]
pub async fn admin_update_user_email(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    req: web::Json<AdminUpdateUserEmailRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_id_uuid = user_id.parse::<Uuid>().map_err(|_| {
        crate::error::AuthError::ValidationFailed("Invalid user ID format".to_string())
    })?;

    let updated_user = user_service
        .update_user_email(user_id_uuid, &req.new_email)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "message": "User email updated successfully",
        "success": true,
        "user": updated_user
    })))
}

/// Admin endpoint to update user phone
#[put("/{user_id}/phone")]
pub async fn admin_update_user_phone(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    req: web::Json<AdminUpdateUserPhoneRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_id_uuid = user_id.parse::<Uuid>().map_err(|_| {
        crate::error::AuthError::ValidationFailed("Invalid user ID format".to_string())
    })?;

    let updated_user = user_service
        .update_user_phone(user_id_uuid, &req.phone)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "message": "User phone updated successfully",
        "success": true,
        "user": updated_user
    })))
}

/// Admin endpoint to update user name
#[put("/{user_id}/name")]
pub async fn admin_update_user_name(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    req: web::Json<AdminUpdateUserNameRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_id_uuid = user_id.parse::<Uuid>().map_err(|_| {
        crate::error::AuthError::ValidationFailed("Invalid user ID format".to_string())
    })?;

    let updated_user = user_service
        .update_user_name(user_id_uuid, &req.name)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "message": "User name updated successfully",
        "success": true,
        "user": updated_user
    })))
}

/// Admin endpoint to update user avatar
#[put("/{user_id}/avatar")]
pub async fn admin_update_user_avatar(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    req: web::Json<AdminUpdateUserAvatarRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_id_uuid = user_id.parse::<Uuid>().map_err(|_| {
        crate::error::AuthError::ValidationFailed("Invalid user ID format".to_string())
    })?;

    let updated_user = user_service
        .update_user_avatar(user_id_uuid, &req.avatar_path)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "message": "User avatar updated successfully",
        "success": true,
        "user": updated_user
    })))
}

/// Admin endpoint to update user verification status
#[put("/{user_id}/verification")]
pub async fn admin_update_user_verification(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    req: web::Json<AdminUpdateUserVerificationRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_id_uuid = user_id.parse::<Uuid>().map_err(|_| {
        crate::error::AuthError::ValidationFailed("Invalid user ID format".to_string())
    })?;

    let email_verified_time = if req.email_verified {
        Some(Utc::now())
    } else {
        None
    };
    let phone_verified = req.phone_verified;

    let updated_user = user_service
        .update_user_verification(user_id_uuid, email_verified_time, phone_verified)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "message": "User verification status updated successfully",
        "success": true,
        "user": updated_user
    })))
}

/// Admin endpoint to lock user account
#[put("/{user_id}/lock")]
pub async fn admin_lock_user_account(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    req: web::Json<AdminLockUserAccountRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_id_uuid = user_id.parse::<Uuid>().map_err(|_| {
        crate::error::AuthError::ValidationFailed("Invalid user ID format".to_string())
    })?;

    let lock_until = if let Some(lock_time_str) = &req.lock_until {
        chrono::DateTime::parse_from_rfc3339(lock_time_str)
            .map_err(|_| {
                crate::error::AuthError::ValidationFailed("Invalid lock time format".to_string())
            })?
            .with_timezone(&Utc)
    } else {
        Utc::now() + chrono::Duration::hours(24) // Default 24 hour lock
    };

    user_service
        .lock_user_account(user_id_uuid, Some(lock_until))
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "message": "User account locked successfully",
        "success": true,
        "lock_until": lock_until.to_rfc3339(),
        "reason": req.reason.clone()
    })))
}

/// Admin endpoint to unlock user account
#[put("/{user_id}/unlock")]
pub async fn admin_unlock_user_account(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    req: web::Json<AdminUnlockUserAccountRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "super_admin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_id_uuid = user_id.parse::<Uuid>().map_err(|_| {
        crate::error::AuthError::ValidationFailed("Invalid user ID format".to_string())
    })?;

    user_service.unlock_user_account(user_id_uuid).await?;

    Ok(HttpResponse::Ok().json(json!({
        "message": "User account unlocked successfully",
        "success": true,
        "reason": req.reason.clone()
    })))
}
