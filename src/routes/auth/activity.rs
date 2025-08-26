use crate::{
    db::DbPool,
    error::AuthResult,
    middleware::extract_user_id_from_request,
    services::{
        activity::{ActivityLogRequest, ActivityService},
        user::UserService,
    },
};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct LogActivityRequest {
    #[validate(length(min = 1, max = 100))]
    pub activity_type: String,
    #[validate(length(min = 1, max = 500))]
    pub description: String,
    #[validate(length(max = 1000))]
    pub metadata: Option<String>,
    #[validate(length(min = 1, max = 45))]
    pub ip_address: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ActivityResponse {
    pub message: String,
    pub success: bool,
}

#[post("/log")]
pub async fn log_user_activity(
    pool: web::Data<DbPool>,
    req: web::Json<LogActivityRequest>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let activity_request = ActivityLogRequest {
        user_id: current_user_id,
        activity_type: req.activity_type.clone(),
        description: req.description.clone(),
        metadata: req
            .metadata
            .as_ref()
            .map(|s| serde_json::from_str(s).unwrap_or(serde_json::Value::Null)),
        ip_address: req.ip_address.clone(),
        user_agent: req.user_agent.clone(),
    };

    activity_service.log_activity(activity_request).await?;

    Ok(HttpResponse::Ok().json(ActivityResponse {
        message: "Activity logged successfully".to_string(),
        success: true,
    }))
}

#[get("/my-activities")]
pub async fn get_my_activities(
    pool: web::Data<DbPool>,
    query: web::Query<std::collections::HashMap<String, String>>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let limit = query
        .get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(50);

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let activities = activity_service
        .get_user_activities(current_user_id, Some(limit))
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "activities": activities,
        "success": true
    })))
}

#[get("/recent")]
pub async fn get_recent_activities(
    pool: web::Data<DbPool>,
    query: web::Query<std::collections::HashMap<String, String>>,
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

    let limit = query
        .get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(100);

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let activities = activity_service.get_recent_activities(limit).await?;

    Ok(HttpResponse::Ok().json(json!({
        "activities": activities,
        "success": true
    })))
}

#[get("/summary")]
pub async fn get_activity_summary(
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

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let summary = activity_service.get_activity_summary().await?;

    Ok(HttpResponse::Ok().json(json!({
        "summary": summary,
        "success": true
    })))
}

#[get("/stats/today")]
pub async fn get_logins_today(
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

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let count = activity_service.get_total_logins_today().await?;

    Ok(HttpResponse::Ok().json(json!({
        "logins_today": count,
        "success": true
    })))
}

#[get("/stats/week")]
pub async fn get_logins_week(
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

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let count = activity_service.get_total_logins_week().await?;

    Ok(HttpResponse::Ok().json(json!({
        "logins_week": count,
        "success": true
    })))
}

#[get("/stats/month")]
pub async fn get_logins_month(
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

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let count = activity_service.get_total_logins_month().await?;

    Ok(HttpResponse::Ok().json(json!({
        "logins_month": count,
        "success": true
    })))
}

#[get("/stats/failed-attempts")]
pub async fn get_failed_login_attempts(
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

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let count = activity_service.get_failed_login_attempts().await?;

    Ok(HttpResponse::Ok().json(json!({
        "failed_login_attempts": count,
        "success": true
    })))
}

#[get("/user/{user_id}/audit")]
pub async fn get_user_audit_logs(
    pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
    query: web::Query<std::collections::HashMap<String, String>>,
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

    let limit = query
        .get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(100);

    let activity_service = ActivityService::new(pool.get_ref().clone());

    let audit_logs = activity_service
        .get_user_audit_logs(user_id.into_inner(), limit, 1)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "audit_logs": audit_logs,
        "success": true
    })))
}
