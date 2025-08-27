use crate::config::AppConfig;
use crate::db::DbPool;
use crate::services::core::auth::{AuthService, RegisterRequest};
use crate::services::core::session::SessionService;
use crate::services::core::user::UserService;
use crate::services::utils::email::EmailService;
use crate::services::{activity::ActivityService, utils::jwt::JwtService};
use actix_web::{post, web, HttpResponse};
use validator::Validate;

#[post("/register")]
pub async fn register_user(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<RegisterRequest>,
    http_req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    // Create services
    let jwt_service = JwtService::new(config.jwt.clone())?;
    let session_service = SessionService::new(pool.get_ref().clone());
    let activity_service = ActivityService::new(pool.get_ref().clone());
    let user_service = UserService::new(pool.get_ref().clone());
    let auth_service = AuthService::new(
        pool.get_ref().clone(),
        jwt_service,
        session_service,
        activity_service,
        user_service,
        config.get_ref().clone(),
    );

    let request_data = req.into_inner();
    let response = auth_service
        .register(request_data.clone(), &http_req)
        .await?;

    // Send email verification link with JWT token (don't fail registration if email fails)
    let email_service = EmailService::new(config.email.clone());
    if let Ok(email_svc) = email_service {
        // Generate JWT token for email verification
        let jwt_service = JwtService::new(config.jwt.clone())?;
        let verification_token = jwt_service.generate_access_token(
            response.user.id,
            &request_data.email,
            "unverified", // Special role for unverified users
        )?;

        // Create verification URL with JWT token
        let verification_url = format!(
            "{}/verify-email?token={}",
            config.frontend_url, verification_token
        );

        let _ = email_svc
            .send_verification_link(&request_data.email, &request_data.name, &verification_url)
            .await;
    }

    Ok(HttpResponse::Created().json(response))
}
