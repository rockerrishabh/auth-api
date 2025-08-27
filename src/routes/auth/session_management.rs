use crate::{
    db::DbPool,
    error::AuthResult,
    middleware::extract_user_id_from_request,
    services::core::{session::SessionService, user::UserService},
};
use actix_web::{delete, get, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateSessionRequest {
    #[validate(length(min = 1, max = 255))]
    pub device_info: Option<String>,
    #[validate(length(min = 1, max = 45))]
    pub ip_address: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionManagementResponse {
    pub message: String,
    pub success: bool,
}

#[get("/current")]
pub async fn get_current_session(
    pool: web::Data<DbPool>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    // Extract user ID for authentication (used implicitly through token validation)
    extract_user_id_from_request(&http_req).map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Extract token from Authorization header
    let auth_header = http_req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::error::AuthError::InvalidToken)?;

    let session_service = SessionService::new(pool.get_ref().clone());

    let session = session_service
        .get_session(auth_header)
        .await?
        .ok_or_else(|| {
            crate::error::AuthError::ValidationFailed("Session not found".to_string())
        })?;

    Ok(HttpResponse::Ok().json(session))
}

#[get("/all")]
pub async fn get_all_user_sessions(
    pool: web::Data<DbPool>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    let _current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let session_service = SessionService::new(pool.get_ref().clone());

    let sessions = session_service
        .get_user_sessions(_current_user_id, 1, 10)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "sessions": sessions,
        "success": true
    })))
}

#[delete("/revoke/{session_id}")]
pub async fn revoke_specific_session(
    pool: web::Data<DbPool>,
    session_id: web::Path<Uuid>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let session_service = SessionService::new(pool.get_ref().clone());

    // Verify the session belongs to the current user
    let sessions = session_service
        .get_user_sessions(current_user_id, 1, 10)
        .await?;

    let session_id_inner = session_id.into_inner();
    let session_exists = sessions.iter().any(|s| s.id == session_id_inner);
    if !session_exists {
        return Err(crate::error::AuthError::ValidationFailed(
            "Session not found or doesn't belong to user".to_string(),
        ));
    }

    // Revoke the specific session
    let revoked = session_service
        .revoke_user_session(current_user_id, session_id_inner)
        .await?;

    if revoked {
        Ok(HttpResponse::Ok().json(SessionManagementResponse {
            message: "Session revoked successfully".to_string(),
            success: true,
        }))
    } else {
        Err(crate::error::AuthError::ValidationFailed(
            "Failed to revoke session".to_string(),
        ))
    }
}

#[delete("/revoke-other-sessions")]
pub async fn revoke_other_sessions(
    pool: web::Data<DbPool>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    // Extract current session token
    let current_token = http_req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::error::AuthError::InvalidToken)?;

    let session_service = SessionService::new(pool.get_ref().clone());

    let revoked_count = session_service
        .revoke_other_user_sessions(current_user_id, current_token)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "message": format!("Revoked {} other sessions", revoked_count),
        "revoked_count": revoked_count,
        "success": true
    })))
}

#[get("/count")]
pub async fn get_session_count(
    pool: web::Data<DbPool>,
    http_req: HttpRequest,
) -> AuthResult<HttpResponse> {
    let current_user_id = extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let session_service = SessionService::new(pool.get_ref().clone());

    let count = session_service
        .get_user_sessions_count(current_user_id)
        .await?;

    Ok(HttpResponse::Ok().json(json!({
        "session_count": count,
        "success": true
    })))
}

#[get("/statistics")]
pub async fn get_session_statistics(
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

    let session_service = SessionService::new(pool.get_ref().clone());

    let total_sessions = session_service.get_total_sessions_count().await?;
    let active_sessions = session_service.get_active_sessions_count().await?;

    Ok(HttpResponse::Ok().json(json!({
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "success": true
    })))
}
