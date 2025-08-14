use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_httpauth::extractors::bearer::{BearerAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // Subject (user ID)
    pub email: String,
    pub role: String,
    pub exp: i64,     // Expiration time
    pub iat: i64,     // Issued at
    pub token_type: TokenType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
    EmailVerification,
    PasswordReset,
}

pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiry: Duration,
    pub refresh_token_expiry: Duration,
    pub email_verification_expiry: Duration,
    pub password_reset_expiry: Duration,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string()),
            access_token_expiry: Duration::hours(1),
            refresh_token_expiry: Duration::days(30),
            email_verification_expiry: Duration::hours(24),
            password_reset_expiry: Duration::hours(1),
        }
    }
}

impl JwtConfig {
    pub fn generate_access_token(&self, user_id: Uuid, email: &str, role: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: (now + self.access_token_expiry).timestamp(),
            iat: now.timestamp(),
            token_type: TokenType::Access,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
    }

    pub fn generate_refresh_token(&self, user_id: Uuid, email: &str, role: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: (now + self.refresh_token_expiry).timestamp(),
            iat: now.timestamp(),
            token_type: TokenType::Refresh,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
    }

    pub fn generate_email_verification_token(&self, user_id: Uuid, email: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: "user".to_string(),
            exp: (now + self.email_verification_expiry).timestamp(),
            iat: now.timestamp(),
            token_type: TokenType::EmailVerification,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
    }

    pub fn generate_password_reset_token(&self, user_id: Uuid, email: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: "user".to_string(),
            exp: (now + self.password_reset_expiry).timestamp(),
            iat: now.timestamp(),
            token_type: TokenType::PasswordReset,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
    }

    pub fn verify_token(&self, token: &str) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        )
    }

    pub fn verify_token_type(&self, token: &str, expected_type: TokenType) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
        let token_data = self.verify_token(token)?;
        
        if token_data.claims.token_type != expected_type {
            return Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken));
        }
        
        Ok(token_data)
    }
}

// Middleware for JWT authentication
pub async fn jwt_middleware(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let config = JwtConfig::default();
    let token = credentials.token();

    match config.verify_token_type(token, TokenType::Access) {
        Ok(token_data) => {
            req.extensions_mut().insert(token_data.claims);
            Ok(req)
        }
        Err(_) => {
            let config = Config::default().realm("Restricted area");
            Err((AuthenticationError::from(config).into(), req))
        }
    }
}

// Helper function to extract claims from request
pub fn get_claims_from_request(req: &ServiceRequest) -> Option<Claims> {
    req.extensions().get::<Claims>().cloned()
}