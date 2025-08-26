use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: u64,
    pub idle_timeout: u64,
    pub max_lifetime: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiry: u64,
    pub refresh_token_expiry: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_email: String,
    pub from_name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub argon2_memory_cost: u32, // Reserved for future custom argon2 configuration
    pub argon2_time_cost: u32,   // Reserved for future custom argon2 configuration
    pub argon2_parallelism: u32, // Reserved for future custom argon2 configuration
    pub session_timeout: u64,
    pub max_failed_attempts: u32,
    pub lockout_duration: u64, // Reserved for future account lockout feature
}

#[derive(Debug, Deserialize, Clone)]
pub struct UploadConfig {
    pub dir: String,
    pub max_size: u32,
    pub image_max_width: u32,
    pub image_max_height: u32,
    pub image_quality: u32,
    pub generate_thumbnails: bool,
    pub thumbnail_size: u32,
    pub allowed_types: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub environment: String,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub email: EmailConfig,
    pub security: SecurityConfig,
    pub upload: UploadConfig,
    pub frontend_url: String,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        // First, try to get environment from APP_ENVIRONMENT or fallback to ENVIRONMENT
        let env = env::var("APP_ENVIRONMENT")
            .or_else(|_| env::var("ENVIRONMENT"))
            .unwrap_or_else(|_| "development".into());

        let config = Config::builder()
            // Only load config files if they exist, otherwise rely on environment variables
            .add_source(File::with_name("config/default.toml").required(false))
            .add_source(File::with_name(&format!("config/{}.toml", env)).required(false))
            .add_source(File::with_name("config/local.toml").required(false))
            .add_source(Environment::with_prefix("APP"))
            .build()?;

        config.try_deserialize()
    }

    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }

    pub fn is_development(&self) -> bool {
        self.environment == "development"
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 5000,
            environment: "development".to_string(),
            database: DatabaseConfig {
                url: "postgres://user:password@localhost/auth_db".to_string(),
                max_connections: 10,
                min_connections: 2,
                connect_timeout: 10,
                idle_timeout: 300,
                max_lifetime: 3600,
            },
            jwt: JwtConfig {
                secret: "your-secret-key".to_string(),
                access_token_expiry: 3600,     // 1 hour
                refresh_token_expiry: 2592000, // 30 days
            },
            email: EmailConfig {
                smtp_host: "smtp.gmail.com".to_string(),
                smtp_port: 587,
                smtp_username: "your-email@gmail.com".to_string(),
                smtp_password: "your-password".to_string(),
                from_email: "noreply@yourapp.com".to_string(),
                from_name: "Your App".to_string(),
            },
            security: SecurityConfig {
                argon2_memory_cost: 65536, // 64MB
                argon2_time_cost: 3,
                argon2_parallelism: 1,
                session_timeout: 3600, // 1 hour
                max_failed_attempts: 5,
                lockout_duration: 900, // 15 minutes
            },
            upload: UploadConfig {
                dir: "./static".to_string(),
                max_size: 10485760, // 10MB
                image_max_width: 1920,
                image_max_height: 1080,
                image_quality: 75,
                generate_thumbnails: true,
                thumbnail_size: 300,
                allowed_types: vec![
                    "jpg".to_string(),
                    "jpeg".to_string(),
                    "png".to_string(),
                    "gif".to_string(),
                    "webp".to_string(),
                ],
            },
            frontend_url: "http://localhost:3000".to_string(),
        }
    }
}

use crate::error::AuthResult;

impl AppConfig {
    /// Get a boolean setting value with default fallback
    pub fn get_bool_setting(&self, key: &str, default: bool) -> AuthResult<bool> {
        // For now, return defaults since we don't have dynamic settings implemented yet
        // This can be extended later to read from database
        match key {
            "email_verification_required" => Ok(default), // Use the passed default
            "maintenance_mode" => Ok(false),
            "registration_enabled" => Ok(true),
            "two_factor_required" => Ok(false),
            _ => Ok(default),
        }
    }
}
