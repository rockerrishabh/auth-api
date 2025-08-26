use crate::db::DbPool;
use crate::middleware::extract_user_id_from_request;
use crate::services::session::SessionService;
use actix_web::{post, web, HttpRequest, HttpResponse};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub message: String,
    pub success: bool,
}

#[post("/logout")]
pub async fn logout_user(
    pool: web::Data<DbPool>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id =
        extract_user_id_from_request(&req).map_err(|_| crate::error::AuthError::InvalidToken)?;

    let session_service = SessionService::new(pool.get_ref().clone());

    // Revoke all sessions for the user
    let revoked_count = session_service.revoke_all_user_sessions(user_id).await?;

    // Clear the refresh token cookie
    let refresh_token_cookie = actix_web::cookie::Cookie::build("refresh_token", "")
        .http_only(true)
        .secure(true) // Always secure for logout
        .same_site(actix_web::cookie::SameSite::Strict)
        .path("/api/v1/auth")
        .max_age(actix_web::cookie::time::Duration::seconds(0)) // Expire immediately
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(refresh_token_cookie)
        .json(LogoutResponse {
            message: format!(
                "Successfully logged out. {} sessions revoked.",
                revoked_count
            ),
            success: true,
        }))
}
