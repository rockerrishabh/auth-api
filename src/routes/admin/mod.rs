// Admin routes modules
pub mod audit;
pub mod dashboard;
pub mod performance;
pub mod session_management;
pub mod system;
pub mod testing;
pub mod users;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::middleware::{extract_user_id_from_request, AuthMiddleware, RoleMiddleware};
use crate::services::core::user::UserService;
use actix_web::{delete, get, put, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRoleRequest {
    #[validate(length(min = 1, message = "Role is required"))]
    pub role: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserStatusRequest {
    #[validate(length(min = 1, message = "Status is required"))]
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct AdminResponse {
    pub message: String,
    pub success: bool,
}

#[get("/users")]
pub async fn list_users(
    pool: web::Data<DbPool>,
    query: web::Query<std::collections::HashMap<String, String>>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Verify admin permissions from JWT token
    let current_user_id =
        extract_user_id_from_request(&req).map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Check if current user has admin role
    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "superadmin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_service = UserService::new(pool.get_ref().clone());

    let page = query.get("page").and_then(|p| p.parse::<i64>().ok());
    let per_page = query.get("per_page").and_then(|p| p.parse::<i64>().ok());
    let role_filter = query.get("role").map(|r| r.as_str());
    let status_filter = query.get("status").map(|r| r.as_str());

    let (users, total) = user_service
        .list_users(page, per_page, role_filter, status_filter)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "users": users,
        "total": total,
        "page": page.unwrap_or(1),
        "per_page": per_page.unwrap_or(10)
    })))
}

#[get("/users/{user_id}")]
pub async fn get_user(
    pool: web::Data<DbPool>,
    user_id: web::Path<uuid::Uuid>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Verify admin permissions from JWT token
    let current_user_id =
        extract_user_id_from_request(&req).map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Check if current user has admin role
    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "superadmin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_service = UserService::new(pool.get_ref().clone());
    let user = user_service.get_user_by_id(user_id.into_inner()).await?;

    match user {
        Some(user) => Ok(HttpResponse::Ok().json(user)),
        None => Err(crate::error::AuthError::UserNotFound),
    }
}

#[put("/users/{user_id}/role")]
pub async fn update_user_role(
    pool: web::Data<DbPool>,
    user_id: web::Path<uuid::Uuid>,
    req: web::Json<UpdateUserRoleRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Check if current user has admin role
    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "superadmin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .update_user_role(user_id.into_inner(), &req.role)
        .await?;

    Ok(HttpResponse::Ok().json(AdminResponse {
        message: "User role updated successfully".to_string(),
        success: true,
    }))
}

#[put("/users/{user_id}/status")]
pub async fn update_user_status(
    pool: web::Data<DbPool>,
    user_id: web::Path<uuid::Uuid>,
    req: web::Json<UpdateUserStatusRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Verify admin permissions from JWT token
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Check if current user has admin role
    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "superadmin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_service = UserService::new(pool.get_ref().clone());
    user_service
        .update_user_status(user_id.into_inner(), &req.status)
        .await?;

    Ok(HttpResponse::Ok().json(AdminResponse {
        message: "User status updated successfully".to_string(),
        success: true,
    }))
}

#[delete("/users/{user_id}")]
pub async fn delete_user(
    pool: web::Data<DbPool>,
    user_id: web::Path<uuid::Uuid>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Verify admin permissions from JWT token
    let current_user_id =
        extract_user_id_from_request(&req).map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Check if current user has admin role
    let user_service = UserService::new(pool.get_ref().clone());
    let current_user = user_service
        .get_user_by_id(current_user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    if current_user.role != "admin" && current_user.role != "superadmin" {
        return Err(crate::error::AuthError::InsufficientPermissions);
    }

    let user_service = UserService::new(pool.get_ref().clone());
    let deleted = user_service.delete_user(user_id.into_inner()).await?;

    if deleted {
        Ok(HttpResponse::Ok().json(AdminResponse {
            message: "User deleted successfully".to_string(),
            success: true,
        }))
    } else {
        Err(crate::error::AuthError::UserNotFound)
    }
}

pub fn configure_admin_routes(
    cfg: &mut web::ServiceConfig,
    auth_middleware: AuthMiddleware,
    db_pool: DbPool,
    config: AppConfig,
) {
    cfg.service(
        web::scope("/admin")
            .wrap(auth_middleware)
            .wrap(RoleMiddleware::new("admin".to_string(), db_pool))
            .service(
                web::scope("/users")
                    .service(list_users)
                    .service(get_user)
                    .service(update_user_role)
                    .service(update_user_status)
                    .service(delete_user)
                    .service(users::search_users)
                    .service(users::search_user_by_username)
                    .service(users::bulk_update_users)
                    .service(users::get_user_statistics)
                    .service(users::export_users)
                    .service(users::get_user_preferences)
                    .service(users::update_user_preferences),
            )
            .service(web::scope("/sessions").service(session_management::get_session_statistics))
            .service(
                web::scope("/dashboard")
                    .service(dashboard::get_dashboard_stats)
                    .service(dashboard::get_activity_stats)
                    .service(dashboard::get_role_distribution)
                    .service(dashboard::get_system_health)
                    .service(dashboard::get_system_info)
                    .service(dashboard::get_user_statistics)
                    .service(dashboard::get_activity_timeline),
            )
            .service(
                web::scope("/audit")
                    .service(audit::get_audit_logs)
                    .service(audit::get_audit_summary)
                    .service(audit::get_user_audit_logs),
            )
            .service(
                web::scope("/system")
                    .service(system::get_system_config)
                    .service(system::update_system_config)
                    .service(system::initialize_system_settings)
                    .service(system::get_all_system_settings)
                    .service(system::get_system_health)
                    .service(system::get_system_monitoring)
                    .service(system::get_cache_stats)
                    .service(system::clear_cache)
                    .app_data(web::Data::new(config)),
            )
            .service(
                web::scope("/performance")
                    .service(performance::get_performance_issues)
                    .service(performance::get_bundle_analysis)
                    .service(performance::get_render_metrics)
                    .service(performance::run_performance_analysis)
                    .service(performance::get_realtime_metrics),
            )
            .service(
                web::scope("/testing")
                    .service(testing::get_test_suites)
                    .service(testing::get_test_results)
                    .service(testing::get_performance_metrics)
                    .service(testing::run_test_suite)
                    .service(testing::get_test_types),
            ),
    );
}
