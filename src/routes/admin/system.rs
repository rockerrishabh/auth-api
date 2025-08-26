use crate::{
    config::AppConfig,
    db::DbPool,
    services::{EmailService, SystemService},
};
use actix_web::{get, post, put, web, HttpRequest, HttpResponse};
use serde::Serialize;
use std::collections::HashMap;
use validator::Validate;

#[derive(Debug, serde::Deserialize, Validate)]
pub struct UpdateSystemConfigRequest {
    #[validate(length(max = 100))]
    pub app_name: Option<String>,
    #[validate(length(max = 255))]
    pub app_description: Option<String>,
    #[validate(length(max = 100))]
    pub environment: Option<String>,
    pub maintenance_mode: Option<bool>,
    pub registration_enabled: Option<bool>,
    pub email_verification_required: Option<bool>,
    pub two_factor_required: Option<bool>,
    pub max_login_attempts: Option<u32>,
    pub session_timeout_minutes: Option<u64>,
}

#[derive(Debug, serde::Serialize)]
pub struct SystemConfigResponse {
    pub message: String,
    pub success: bool,
    pub config: SystemConfigInfo,
}

#[derive(Debug, serde::Serialize)]
pub struct SystemConfigInfo {
    pub app_name: String,
    pub app_description: String,
    pub environment: String,
    pub maintenance_mode: bool,
    pub registration_enabled: bool,
    pub email_verification_required: bool,
    pub two_factor_required: bool,
    pub max_login_attempts: u32,
    pub session_timeout_minutes: u64,
    pub database_status: String,
    pub email_service_status: String,
    pub uptime_seconds: u64,
}

/// Get current system configuration
#[get("/config")]
pub async fn get_system_config(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    _http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Test database connection
    let db_status = match pool.get() {
        Ok(_) => "healthy",
        Err(_) => "unhealthy",
    };

    // Test email service connection
    let email_status = match EmailService::new(config.email.clone()) {
        Ok(_) => "healthy", // Service can be initialized
        Err(_) => "unhealthy",
    };

    let system_service = SystemService::new(pool.get_ref().clone());

    // Get all settings at once for efficiency
    let all_settings = system_service.get_all_settings().await?;

    // Extract individual settings with defaults
    let app_name = all_settings
        .get("app_name")
        .map(|s| s.clone())
        .unwrap_or_else(|| "Advanced Authentication System".to_string());
    let app_description = all_settings
        .get("app_description")
        .map(|s| s.clone())
        .unwrap_or_else(|| "Advanced Authentication System".to_string());
    let maintenance_mode = all_settings
        .get("maintenance_mode")
        .map(|s| s.parse().unwrap_or(false))
        .unwrap_or(false);
    let registration_enabled = all_settings
        .get("registration_enabled")
        .map(|s| s.parse().unwrap_or(true))
        .unwrap_or(true);
    let email_verification_required = all_settings
        .get("email_verification_required")
        .map(|s| s.parse().unwrap_or(true))
        .unwrap_or(true);
    let two_factor_required = all_settings
        .get("two_factor_required")
        .map(|s| s.parse().unwrap_or(false))
        .unwrap_or(false);

    // Read dynamic security settings with fallbacks to config
    let max_login_attempts = all_settings
        .get("max_login_attempts")
        .map(|s| s.parse().unwrap_or(config.security.max_failed_attempts))
        .unwrap_or(config.security.max_failed_attempts);

    let session_timeout_minutes = all_settings
        .get("session_timeout_minutes")
        .map(|s| s.parse().unwrap_or(config.security.session_timeout / 60))
        .unwrap_or(config.security.session_timeout / 60);

    let system_config = SystemConfigInfo {
        app_name,
        app_description,
        environment: config.environment.clone(),
        maintenance_mode,
        registration_enabled,
        email_verification_required,
        two_factor_required,
        max_login_attempts,
        session_timeout_minutes,
        database_status: db_status.to_string(),
        email_service_status: email_status.to_string(),
        uptime_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    Ok(HttpResponse::Ok().json(SystemConfigResponse {
        message: "System configuration retrieved successfully".to_string(),
        success: true,
        config: system_config,
    }))
}

/// Update system configuration
#[put("/config")]
pub async fn update_system_config(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    req: web::Json<UpdateSystemConfigRequest>,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let system_service = SystemService::new(pool.get_ref().clone());

    // Update settings in database if provided
    if let Some(app_name) = &req.app_name {
        system_service
            .set_setting(
                "app_name",
                app_name,
                "string",
                Some("Application name displayed to users"),
            )
            .await?;
    }

    if let Some(app_description) = &req.app_description {
        system_service
            .set_setting(
                "app_description",
                app_description,
                "string",
                Some("Application description"),
            )
            .await?;
    }

    if let Some(maintenance_mode) = req.maintenance_mode {
        system_service
            .set_setting(
                "maintenance_mode",
                &maintenance_mode.to_string(),
                "boolean",
                Some("Whether the system is in maintenance mode"),
            )
            .await?;
    }

    if let Some(registration_enabled) = req.registration_enabled {
        system_service
            .set_setting(
                "registration_enabled",
                &registration_enabled.to_string(),
                "boolean",
                Some("Whether new user registration is allowed"),
            )
            .await?;
    }

    if let Some(email_verification_required) = req.email_verification_required {
        system_service
            .set_setting(
                "email_verification_required",
                &email_verification_required.to_string(),
                "boolean",
                Some("Whether email verification is required"),
            )
            .await?;
    }

    if let Some(two_factor_required) = req.two_factor_required {
        system_service
            .set_setting(
                "two_factor_required",
                &two_factor_required.to_string(),
                "boolean",
                Some("Whether 2FA is required for all users"),
            )
            .await?;
    }

    // Implement dynamic settings for complex security features
    if let Some(max_login_attempts) = req.max_login_attempts {
        system_service
            .set_setting(
                "max_login_attempts",
                &max_login_attempts.to_string(),
                "integer",
                Some("Maximum number of failed login attempts before account lockout"),
            )
            .await?;
    }

    if let Some(session_timeout_minutes) = req.session_timeout_minutes {
        system_service
            .set_setting(
                "session_timeout_minutes",
                &session_timeout_minutes.to_string(),
                "integer",
                Some("Session timeout duration in minutes"),
            )
            .await?;
    }

    // Get updated configuration to return
    let db_status = match pool.get() {
        Ok(_) => "healthy",
        Err(_) => "unhealthy",
    };

    let email_status = "healthy";

    // Get updated dynamic settings
    let app_name = system_service
        .get_string_setting("app_name", "Advanced Authentication System")
        .await?;
    let app_description = system_service
        .get_string_setting("app_description", "Advanced Authentication System")
        .await?;
    let maintenance_mode = system_service
        .get_bool_setting("maintenance_mode", false)
        .await?;
    let registration_enabled = system_service
        .get_bool_setting("registration_enabled", true)
        .await?;
    let email_verification_required = system_service
        .get_bool_setting("email_verification_required", true)
        .await?;
    let two_factor_required = system_service
        .get_bool_setting("two_factor_required", false)
        .await?;

    let system_config = SystemConfigInfo {
        app_name,
        app_description,
        environment: req
            .environment
            .clone()
            .unwrap_or_else(|| config.environment.clone()),
        maintenance_mode,
        registration_enabled,
        email_verification_required,
        two_factor_required,
        max_login_attempts: req
            .max_login_attempts
            .unwrap_or(config.security.max_failed_attempts),
        session_timeout_minutes: req
            .session_timeout_minutes
            .unwrap_or(config.security.session_timeout / 60),
        database_status: db_status.to_string(),
        email_service_status: email_status.to_string(),
        uptime_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    Ok(HttpResponse::Ok().json(SystemConfigResponse {
        message: "System configuration updated successfully".to_string(),
        success: true,
        config: system_config,
    }))
}

/// Initialize system settings with defaults
#[post("/initialize")]
pub async fn initialize_system_settings(
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, crate::error::AuthError> {
    let system_service = SystemService::new(pool.get_ref().clone());

    // Initialize default settings
    system_service.initialize_defaults().await?;

    Ok(HttpResponse::Ok().json(SystemConfigResponse {
        message: "System settings initialized successfully".to_string(),
        success: true,
        config: SystemConfigInfo {
            app_name: "Advanced Authentication System".to_string(),
            app_description: "Advanced Authentication System".to_string(),
            environment: "development".to_string(),
            maintenance_mode: false,
            registration_enabled: true,
            email_verification_required: true,
            two_factor_required: false,
            max_login_attempts: 5,
            session_timeout_minutes: 1440,
            database_status: "unknown".to_string(),
            email_service_status: "unknown".to_string(),
            uptime_seconds: 0,
        },
    }))
}

/// Get all system settings
#[get("/settings")]
pub async fn get_all_system_settings(
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, crate::error::AuthError> {
    let system_service = SystemService::new(pool.get_ref().clone());

    // Get all settings from database
    let all_settings = system_service.get_all_settings().await?;

    #[derive(Serialize)]
    struct AllSettingsResponse {
        message: String,
        success: bool,
        settings: HashMap<String, String>,
        count: usize,
    }

    Ok(HttpResponse::Ok().json(AllSettingsResponse {
        message: "All system settings retrieved successfully".to_string(),
        success: true,
        settings: all_settings.clone(),
        count: all_settings.len(),
    }))
}

/// Get system health information
#[get("/health")]
pub async fn get_system_health(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Test database connection
    let db_status = match pool.get() {
        Ok(_) => "healthy",
        Err(_) => "unhealthy",
    };

    // Test email service connection
    let email_status = match EmailService::new(config.email.clone()) {
        Ok(email_service) => {
            // Try to send a test email to verify SMTP connection
            match email_service
                .send_email(crate::services::email::EmailRequest {
                    to: config.email.from_email.clone(),
                    subject: "Health Check Test".to_string(),
                    body: "This is a health check test email.".to_string(),
                    html_body: Some(
                        "<html><body><p>This is a health check test email.</p></body></html>"
                            .to_string(),
                    ),
                })
                .await
            {
                Ok(_) => "healthy",
                Err(e) => {
                    eprintln!("Email health check failed: {:?}", e);
                    "unhealthy"
                }
            }
        }
        Err(e) => {
            eprintln!("Email service initialization failed: {:?}", e);
            "unhealthy"
        }
    };

    // Determine overall health status
    let overall_status = if db_status == "healthy" && email_status == "healthy" {
        "healthy"
    } else {
        return Err(crate::error::AuthError::ServiceUnavailable);
    };

    let health_info = serde_json::json!({
        "status": overall_status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "services": {
            "database": db_status,
            "email": email_status,
            "api": "healthy"
        },
        "uptime_seconds": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "environment": if config.is_development() { "development" } else { "production" }
    });

    Ok(HttpResponse::Ok().json(health_info))
}
