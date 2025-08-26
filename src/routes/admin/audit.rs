use crate::{db::DbPool, services::ActivityService};
use actix_web::{get, web, HttpRequest, HttpResponse};

#[derive(Debug, serde::Serialize)]
pub struct AuditLogResponse {
    pub logs: Vec<AuditLogEntry>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct AuditLogEntry {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub activity_type: String,
    pub description: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Get audit logs with pagination
#[get("/logs")]
pub async fn get_audit_logs(
    pool: web::Data<DbPool>,
    query: web::Query<std::collections::HashMap<String, String>>,
    _http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let page = query
        .get("page")
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(1);
    let per_page = query
        .get("per_page")
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(50);
    let activity_type = query.get("activity_type").cloned();
    let user_id = query
        .get("user_id")
        .and_then(|u| u.parse::<uuid::Uuid>().ok());

    let activity_service = ActivityService::new(pool.get_ref().clone());

    // Get audit logs with filters
    let logs = activity_service
        .get_audit_logs(page, per_page, activity_type.as_deref(), user_id)
        .await?;

    let total = activity_service
        .get_total_audit_logs(activity_type.as_deref(), user_id)
        .await?;

    let response = AuditLogResponse {
        logs: logs
            .into_iter()
            .map(|log| AuditLogEntry {
                id: log.id,
                user_id: log.user_id,
                activity_type: log.activity_type,
                description: log.description,
                ip_address: log.ip_address,
                user_agent: log.user_agent,
                created_at: log.created_at,
            })
            .collect(),
        total,
        page,
        per_page,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get audit log summary statistics
#[get("/summary")]
pub async fn get_audit_summary(
    pool: web::Data<DbPool>,
    _http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let activity_service = ActivityService::new(pool.get_ref().clone());

    let summary = activity_service.get_activity_summary().await?;

    Ok(HttpResponse::Ok().json(summary))
}

/// Get user-specific audit logs
#[get("/user/{user_id}")]
pub async fn get_user_audit_logs(
    pool: web::Data<DbPool>,
    path: web::Path<uuid::Uuid>,
    query: web::Query<std::collections::HashMap<String, String>>,
    _http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id = path.into_inner();
    let page = query
        .get("page")
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(1);
    let per_page = query
        .get("per_page")
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(50);

    let activity_service = ActivityService::new(pool.get_ref().clone());

    // Get user-specific audit logs
    let logs = activity_service
        .get_user_audit_logs(user_id, page, per_page)
        .await?;

    let total = activity_service.get_user_audit_logs_count(user_id).await?;

    let response = AuditLogResponse {
        logs: logs
            .into_iter()
            .map(|log| AuditLogEntry {
                id: log.id,
                user_id: log.user_id,
                activity_type: log.activity_type,
                description: log.description,
                ip_address: log.ip_address,
                user_agent: log.user_agent,
                created_at: log.created_at,
            })
            .collect(),
        total,
        page,
        per_page,
    };

    Ok(HttpResponse::Ok().json(response))
}
