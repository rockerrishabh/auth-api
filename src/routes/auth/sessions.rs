use crate::{db::DbPool, services::core::session::SessionService};
use actix_web::{delete, get, web, HttpRequest, HttpResponse};

#[derive(Debug, serde::Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionInfo>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct SessionInfo {
    pub id: uuid::Uuid,
    pub session_token: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub is_active: bool,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
}

/// Get user's active sessions
#[get("")]
pub async fn get_user_sessions(
    pool: web::Data<DbPool>,
    query: web::Query<std::collections::HashMap<String, String>>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let page = query
        .get("page")
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(1);
    let per_page = query
        .get("per_page")
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(20);

    let session_service = SessionService::new(pool.get_ref().clone());

    // Get user's active sessions
    let sessions = session_service
        .get_user_sessions(user_id, page, per_page)
        .await?;

    let total = session_service.get_user_sessions_count(user_id).await?;

    let response = SessionListResponse {
        sessions: sessions
            .into_iter()
            .map(|s| SessionInfo {
                id: s.id,
                session_token: s.session_token,
                user_agent: s.user_agent,
                ip_address: s.ip_address,
                is_active: s.is_active,
                expires_at: s.expires_at,
                created_at: s.created_at,
                last_activity: s.last_activity,
            })
            .collect(),
        total,
        page,
        per_page,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Revoke a specific session
#[delete("/{session_id}")]
pub async fn revoke_session(
    pool: web::Data<DbPool>,
    path: web::Path<uuid::Uuid>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let session_id = path.into_inner();
    let session_service = SessionService::new(pool.get_ref().clone());

    // Revoke the session (only if it belongs to the user)
    let revoked = session_service
        .revoke_user_session(user_id, session_id)
        .await?;

    if revoked {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Session revoked successfully",
            "success": true
        })))
    } else {
        Err(crate::error::AuthError::ValidationFailed(
            "Session not found or access denied".to_string(),
        ))
    }
}

/// Revoke all other sessions (keep current one)
#[delete("/others")]
pub async fn revoke_other_sessions(
    pool: web::Data<DbPool>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let session_service = SessionService::new(pool.get_ref().clone());

    // Get current session token from request headers
    let current_token = http_req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| crate::error::AuthError::InvalidToken)?;

    // Revoke all other sessions
    let revoked_count = session_service
        .revoke_other_user_sessions(user_id, current_token)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("{} other sessions revoked successfully", revoked_count),
        "success": true,
        "revoked_count": revoked_count
    })))
}
