use config::ConfigError;
use serde::{Deserialize, Deserializer};
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(deserialize_with = "deserialize_u32")]
    pub max_connections: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub min_connections: u32,
    #[serde(deserialize_with = "deserialize_u64")]
    pub connect_timeout: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    pub idle_timeout: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    pub max_lifetime: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    #[serde(deserialize_with = "deserialize_u64")]
    pub access_token_expiry: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    pub refresh_token_expiry: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    #[serde(deserialize_with = "deserialize_u16")]
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_email: String,
    pub from_name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(deserialize_with = "deserialize_u32")]
    pub argon2_memory_cost: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub argon2_time_cost: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub argon2_parallelism: u32,
    #[serde(deserialize_with = "deserialize_u64")]
    pub session_timeout: u64,
    #[serde(deserialize_with = "deserialize_u32")]
    pub max_failed_attempts: u32,
    #[serde(deserialize_with = "deserialize_u64")]
    pub lockout_duration: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UploadConfig {
    pub dir: String,
    #[serde(deserialize_with = "deserialize_u32")]
    pub max_size: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub image_max_width: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub image_max_height: u32,
    #[serde(deserialize_with = "deserialize_u32")]
    pub image_quality: u32,
    pub generate_thumbnails: bool,
    #[serde(deserialize_with = "deserialize_u32")]
    pub thumbnail_size: u32,
    pub allowed_types: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub host: String,
    #[serde(deserialize_with = "deserialize_u16")]
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
        // Manual configuration loading to handle the double underscore format
        let database_url = std::env::var("APP_DATABASE__URL")
            .map_err(|_| ConfigError::NotFound("APP_DATABASE__URL".into()))?;
        let jwt_secret = std::env::var("APP_JWT__SECRET")
            .map_err(|_| ConfigError::NotFound("APP_JWT__SECRET".into()))?;
        let smtp_host = std::env::var("APP_EMAIL__SMTP_HOST")
            .map_err(|_| ConfigError::NotFound("APP_EMAIL__SMTP_HOST".into()))?;
        let smtp_username = std::env::var("APP_EMAIL__SMTP_USERNAME")
            .map_err(|_| ConfigError::NotFound("APP_EMAIL__SMTP_USERNAME".into()))?;
        let smtp_password = std::env::var("APP_EMAIL__SMTP_PASSWORD")
            .map_err(|_| ConfigError::NotFound("APP_EMAIL__SMTP_PASSWORD".into()))?;

        Ok(AppConfig {
            host: std::env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("APP_PORT")
                .unwrap_or_else(|_| "5000".to_string())
                .parse()
                .map_err(|_| ConfigError::Message("Invalid APP_PORT".into()))?,
            environment: std::env::var("APP_ENVIRONMENT")
                .unwrap_or_else(|_| "development".to_string()),
            frontend_url: std::env::var("APP_FRONTEND__URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            database: DatabaseConfig {
                url: database_url,
                max_connections: std::env::var("APP_DATABASE__MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_DATABASE__MAX_CONNECTIONS".into())
                    })?,
                min_connections: std::env::var("APP_DATABASE__MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "2".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_DATABASE__MIN_CONNECTIONS".into())
                    })?,
                connect_timeout: std::env::var("APP_DATABASE__CONNECT_TIMEOUT")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_DATABASE__CONNECT_TIMEOUT".into())
                    })?,
                idle_timeout: std::env::var("APP_DATABASE__IDLE_TIMEOUT")
                    .unwrap_or_else(|_| "300".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_DATABASE__IDLE_TIMEOUT".into())
                    })?,
                max_lifetime: std::env::var("APP_DATABASE__MAX_LIFETIME")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_DATABASE__MAX_LIFETIME".into())
                    })?,
            },
            jwt: JwtConfig {
                secret: jwt_secret,
                access_token_expiry: std::env::var("APP_JWT__ACCESS_TOKEN_EXPIRY")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_JWT__ACCESS_TOKEN_EXPIRY".into())
                    })?,
                refresh_token_expiry: std::env::var("APP_JWT__REFRESH_TOKEN_EXPIRY")
                    .unwrap_or_else(|_| "86400".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_JWT__REFRESH_TOKEN_EXPIRY".into())
                    })?,
            },
            email: EmailConfig {
                smtp_host,
                smtp_port: std::env::var("APP_EMAIL__SMTP_PORT")
                    .unwrap_or_else(|_| "587".to_string())
                    .parse()
                    .map_err(|_| ConfigError::Message("Invalid APP_EMAIL__SMTP_PORT".into()))?,
                smtp_username,
                smtp_password,
                from_email: std::env::var("APP_EMAIL__FROM_EMAIL")
                    .unwrap_or_else(|_| "noreply@localhost".to_string()),
                from_name: std::env::var("APP_EMAIL__FROM_NAME")
                    .unwrap_or_else(|_| "Auth API".to_string()),
            },
            security: SecurityConfig {
                argon2_memory_cost: std::env::var("APP_SECURITY__ARGON2_MEMORY_COST")
                    .unwrap_or_else(|_| "65536".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_SECURITY__ARGON2_MEMORY_COST".into())
                    })?,
                argon2_time_cost: std::env::var("APP_SECURITY__ARGON2_TIME_COST")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_SECURITY__ARGON2_TIME_COST".into())
                    })?,
                argon2_parallelism: std::env::var("APP_SECURITY__ARGON2_PARALLELISM")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_SECURITY__ARGON2_PARALLELISM".into())
                    })?,
                session_timeout: std::env::var("APP_SECURITY__SESSION_TIMEOUT")
                    .unwrap_or_else(|_| "86400".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_SECURITY__SESSION_TIMEOUT".into())
                    })?,
                max_failed_attempts: std::env::var("APP_SECURITY__MAX_FAILED_ATTEMPTS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_SECURITY__MAX_FAILED_ATTEMPTS".into())
                    })?,
                lockout_duration: std::env::var("APP_SECURITY__LOCKOUT_DURATION")
                    .unwrap_or_else(|_| "900".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_SECURITY__LOCKOUT_DURATION".into())
                    })?,
            },
            upload: UploadConfig {
                dir: std::env::var("APP_UPLOAD__DIR").unwrap_or_else(|_| "./static".to_string()),
                max_size: std::env::var("APP_UPLOAD__MAX_SIZE")
                    .unwrap_or_else(|_| "10485760".to_string())
                    .parse()
                    .map_err(|_| ConfigError::Message("Invalid APP_UPLOAD__MAX_SIZE".into()))?,
                image_max_width: std::env::var("APP_UPLOAD__IMAGE_MAX_WIDTH")
                    .unwrap_or_else(|_| "1920".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_UPLOAD__IMAGE_MAX_WIDTH".into())
                    })?,
                image_max_height: std::env::var("APP_UPLOAD__IMAGE_MAX_HEIGHT")
                    .unwrap_or_else(|_| "1080".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_UPLOAD__IMAGE_MAX_HEIGHT".into())
                    })?,
                image_quality: std::env::var("APP_UPLOAD__IMAGE_QUALITY")
                    .unwrap_or_else(|_| "75".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_UPLOAD__IMAGE_QUALITY".into())
                    })?,
                generate_thumbnails: std::env::var("APP_UPLOAD__GENERATE_THUMBNAILS")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
                thumbnail_size: std::env::var("APP_UPLOAD__THUMBNAIL_SIZE")
                    .unwrap_or_else(|_| "300".to_string())
                    .parse()
                    .map_err(|_| {
                        ConfigError::Message("Invalid APP_UPLOAD__THUMBNAIL_SIZE".into())
                    })?,
                allowed_types: vec![
                    "jpg".to_string(),
                    "jpeg".to_string(),
                    "png".to_string(),
                    "gif".to_string(),
                    "webp".to_string(),
                ],
            },
        })
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

// Custom deserialization functions for environment variables
fn deserialize_u16<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u16::from_str(&s).map_err(serde::de::Error::custom)
}

fn deserialize_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u32::from_str(&s).map_err(serde::de::Error::custom)
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u64::from_str(&s).map_err(serde::de::Error::custom)
}
