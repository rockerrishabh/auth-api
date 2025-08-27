use crate::{
    db::DbPool,
    error::AuthResult,
    middleware::extract_user_id_from_request,
    services::core::{session::SessionService, user::UserService},
};
use actix_web::{get, web, HttpRequest, HttpResponse};
use serde_json::json;

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

    if current_user.role != "admin" && current_user.role != "super_admin" {
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
