use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub email: EmailConfig,
    pub jwt: JwtConfig,
    pub upload: UploadConfig,
    pub server: ServerConfig,
}

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_password: String,
    pub from_email: String,
    pub from_name: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub domain: String,
    pub frontend_url: String,
    pub port: u16,
    pub host: String,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub domain: String,
    pub secret: String,
    pub access_token_expires_in: i64, // Access token expiration (short)
    pub refresh_token_expires_in: i64, // Refresh token expiration (long)
    pub verification_token_expires_in: i64, // Email verification expiration (medium)
    pub reset_token_expires_in: i64,  // Password reset expiration (short)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
    EmailVerification,
    PasswordReset,
}

#[derive(Debug, Clone)]
pub struct UploadConfig {
    pub upload_dir: String,
    pub max_width: u32,
    pub max_height: u32,
    pub quality: u8,
    pub generate_thumbnails: bool,
    pub thumbnail_size: u32,
    pub max_size: usize,
    pub allowed_types: Vec<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(AppConfig {
            database_url: get_env_var("DATABASE_URL")?,
            email: EmailConfig::from_env()?,
            jwt: JwtConfig::from_env()?,
            upload: UploadConfig::from_env()?,
            server: ServerConfig::from_env()?,
        })
    }
}

impl EmailConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(EmailConfig {
            smtp_server: get_env_var("SMTP_SERVER")?,
            smtp_port: get_env_var("SMTP_PORT")?.parse().map_err(|_| {
                ConfigError::InvalidFormat("SMTP_PORT must be a valid number".into())
            })?,
            smtp_password: get_env_var("SMTP_PASSWORD")?,
            from_email: get_env_var_or_default("SMTP_FROM_EMAIL", "noreply@example.com"),
            from_name: get_env_var_or_default("SMTP_FROM_NAME", "Auth API"),
        })
    }
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(ServerConfig {
            domain: get_env_var("SERVER_DOMAIN")?,
            frontend_url: get_env_var_or_default("FRONTEND_URL", "http://localhost:3000"),
            port: get_env_var_or_default("PORT", "5000")
                .parse()
                .map_err(|_| ConfigError::InvalidFormat("PORT must be a valid number".into()))?,
            host: get_env_var_or_default("HOST", "0.0.0.0"),
        })
    }
}

impl JwtConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(JwtConfig {
            domain: get_env_var("JWT_DOMAIN")?,
            secret: get_env_var("JWT_SECRET")?,
            access_token_expires_in: get_env_var_or_default("JWT_ACCESS_TOKEN_EXPIRES_IN", "3600")
                .parse()
                .map_err(|_| {
                    ConfigError::InvalidFormat(
                        "JWT_ACCESS_TOKEN_EXPIRES_IN must be a valid number".into(),
                    )
                })?,
            refresh_token_expires_in: get_env_var_or_default(
                "JWT_REFRESH_TOKEN_EXPIRES_IN",
                "86400",
            )
            .parse()
            .map_err(|_| {
                ConfigError::InvalidFormat(
                    "JWT_REFRESH_TOKEN_EXPIRES_IN must be a valid number".into(),
                )
            })?,
            verification_token_expires_in: get_env_var_or_default(
                "JWT_VERIFICATION_TOKEN_EXPIRES_IN",
                "3600",
            )
            .parse()
            .map_err(|_| {
                ConfigError::InvalidFormat(
                    "JWT_VERIFICATION_TOKEN_EXPIRES_IN must be a valid number".into(),
                )
            })?,
            reset_token_expires_in: get_env_var_or_default("JWT_RESET_TOKEN_EXPIRES_IN", "3600")
                .parse()
                .map_err(|_| {
                    ConfigError::InvalidFormat(
                        "JWT_RESET_TOKEN_EXPIRES_IN must be a valid number".into(),
                    )
                })?,
        })
    }
}

impl UploadConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let allowed_types_str =
            get_env_var_or_default("UPLOAD_ALLOWED_TYPES", "jpg,jpeg,png,gif,webp,bmp,tiff");
        let allowed_types = allowed_types_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(UploadConfig {
            upload_dir: get_env_var_or_default("UPLOAD_DIR", "./static"),
            max_size: get_env_var_or_default("UPLOAD_MAX_SIZE", "10485760")
                .parse() // 10MB default
                .map_err(|_| {
                    ConfigError::InvalidFormat("UPLOAD_MAX_SIZE must be a valid number".into())
                })?,
            allowed_types,
            max_width: get_env_var_or_default("IMAGE_MAX_WIDTH", "1920")
                .parse()
                .map_err(|_| {
                    ConfigError::InvalidFormat("IMAGE_MAX_WIDTH must be a valid number".into())
                })?,
            max_height: get_env_var_or_default("IMAGE_MAX_HEIGHT", "1080")
                .parse()
                .map_err(|_| {
                    ConfigError::InvalidFormat("IMAGE_MAX_HEIGHT must be a valid number".into())
                })?,
            quality: get_env_var_or_default("IMAGE_QUALITY", "75")
                .parse()
                .map_err(|_| {
                    ConfigError::InvalidFormat("IMAGE_QUALITY must be a valid number".into())
                })?,
            generate_thumbnails: get_env_var_or_default("GENERATE_THUMBNAILS", "true")
                .parse()
                .map_err(|_| {
                    ConfigError::InvalidFormat("GENERATE_THUMBNAILS must be true or false".into())
                })?,
            thumbnail_size: get_env_var_or_default("THUMBNAIL_SIZE", "300")
                .parse()
                .map_err(|_| {
                    ConfigError::InvalidFormat("THUMBNAIL_SIZE must be a valid number".into())
                })?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Environment variable not found: {0}")]
    NotFound(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

fn get_env_var(key: &str) -> Result<String, ConfigError> {
    env::var(key).map_err(|_| ConfigError::NotFound(key.to_string()))
}

fn get_env_var_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,          // user_id
    pub email: String,      // user email
    pub exp: i64,           // expiration time
    pub iat: i64,           // issued at
    pub purpose: TokenType, // token purpose
}

impl JwtConfig {
    pub fn generate_email_verification_token(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<String, String> {
        use chrono::{Duration, Utc};
        use jsonwebtoken::{encode, EncodingKey, Header};

        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            email: email.to_string(),
            exp: (now + Duration::seconds(self.verification_token_expires_in)).timestamp(),
            iat: now.timestamp(),
            purpose: TokenType::EmailVerification,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
        .map_err(|e| format!("Failed to generate JWT token: {}", e))
    }

    pub fn generate_password_reset_token(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            email: email.to_string(),
            exp: (now + Duration::seconds(self.reset_token_expires_in)).timestamp(),
            iat: now.timestamp(),
            purpose: TokenType::PasswordReset,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
    }

    pub fn verify_token(
        &self,
        token: &str,
    ) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        )
    }

    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            email: email.to_string(),
            exp: (now + Duration::seconds(self.access_token_expires_in)).timestamp(),
            iat: now.timestamp(),
            purpose: TokenType::Access,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
    }

    pub fn generate_refresh_token(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            email: email.to_string(),
            exp: (now + Duration::seconds(self.refresh_token_expires_in)).timestamp(),
            iat: now.timestamp(),
            purpose: TokenType::Refresh,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
    }
}
