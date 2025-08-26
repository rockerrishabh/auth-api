use crate::{config::AppConfig, db::DbPool, error::AuthError};
use actix_web::{get, web, HttpResponse};
use serde_json::json;

#[get("/health")]
pub async fn health_check(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AuthError> {
    // Test database connection
    let db_status = match pool.get() {
        Ok(_) => "healthy",
        Err(e) => {
            println!("Database connection error: {}", e);
            return Err(AuthError::ServiceUnavailable);
        }
    };

    // Test email service
    let email_status = match crate::services::EmailService::new(config.email.clone()) {
        Ok(_) => "healthy",
        Err(e) => {
            println!("Email service error: {}", e);
            return Err(AuthError::ServiceUnavailable);
        }
    };

    // If all services are healthy, return success
    Ok(HttpResponse::Ok().json(json!({
        "status": "healthy",
        "service": "auth-api",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "services": {
            "database": db_status,
            "email": email_status
        }
    })))
}

#[get("/health/detailed")]
pub async fn detailed_health_check(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AuthError> {
    // Test database connection
    let db_status = match pool.get() {
        Ok(_) => "healthy",
        Err(e) => {
            println!("Database connection error in detailed health: {}", e);
            "unhealthy"
        }
    };

    // Test email service
    let email_status = match crate::services::EmailService::new(config.email.clone()) {
        Ok(_) => "healthy",
        Err(e) => {
            println!("Email service error in detailed health: {}", e);
            "unhealthy"
        }
    };

    // Test JWT service
    let jwt_status = match crate::services::jwt::JwtService::new(config.jwt.clone()) {
        Ok(_) => "healthy",
        Err(e) => {
            println!("JWT service error in detailed health: {}", e);
            "unhealthy"
        }
    };

    // Determine overall health status
    let overall_status =
        if db_status == "healthy" && email_status == "healthy" && jwt_status == "healthy" {
            "healthy"
        } else {
            "unhealthy"
        };

    // Always return success with detailed status, don't fail the endpoint
    Ok(HttpResponse::Ok().json(json!({
        "status": overall_status,
        "service": "auth-api",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "components": {
            "database": db_status,
            "jwt_service": jwt_status,
            "email_service": email_status,
            "otp_service": "ready" // OTP service is always ready (no external dependencies)
        }
    })))
}
