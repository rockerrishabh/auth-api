use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::JwtConfig,
    error::{AuthError, AuthResult},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub email: String,      // User email
    pub role: String,       // User role
    pub token_type: String, // Token type (access, refresh, etc.)
    pub exp: usize,         // Expiration time
    pub iat: usize,         // Issued at time
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenValidationResult {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub token_type: String,
    pub expires_at: usize,
}

#[derive(Clone)]
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    config: JwtConfig,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> AuthResult<Self> {
        let encoding_key = EncodingKey::from_secret(config.secret.as_ref());
        let decoding_key = DecodingKey::from_secret(config.secret.as_ref());

        Ok(Self {
            encoding_key,
            decoding_key,
            config,
        })
    }

    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        email: &str,
        role: &str,
    ) -> AuthResult<String> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.access_token_expiry as i64);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            token_type: "access".to_string(),
            exp: expires_at.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::InternalError(format!("Token encoding error: {}", e)))
    }

    pub fn generate_refresh_token(
        &self,
        user_id: Uuid,
        email: &str,
        role: &str,
    ) -> AuthResult<String> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.refresh_token_expiry as i64);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            token_type: "refresh".to_string(),
            exp: expires_at.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::InternalError(format!("Token encoding error: {}", e)))
    }

    pub fn generate_token_pair(
        &self,
        user_id: Uuid,
        email: &str,
        role: &str,
    ) -> AuthResult<TokenPair> {
        let access_token = self.generate_access_token(user_id, email, role)?;
        let refresh_token = self.generate_refresh_token(user_id, email, role)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_expiry,
        })
    }

    pub fn verify_token(&self, token: &str, expected_type: &str) -> AuthResult<Claims> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::InvalidToken,
            })?;

        // Check if token is expired
        if token_data.claims.exp < Utc::now().timestamp() as usize {
            return Err(AuthError::TokenExpired);
        }

        // Check token type
        if token_data.claims.token_type != expected_type {
            return Err(AuthError::InvalidToken);
        }

        Ok(token_data.claims)
    }

    pub fn verify_access_token(&self, token: &str) -> AuthResult<Claims> {
        self.verify_token(token, "access")
    }

    pub fn verify_refresh_token(&self, token: &str) -> AuthResult<Claims> {
        self.verify_token(token, "refresh")
    }

    pub fn extract_user_id_from_token(&self, token: &str, expected_type: &str) -> AuthResult<Uuid> {
        let claims = self.verify_token(token, expected_type)?;
        claims
            .sub
            .parse::<Uuid>()
            .map_err(|e| AuthError::ValidationFailed(format!("Invalid user ID in token: {}", e)))
    }

    pub fn refresh_access_token(&self, refresh_token: &str) -> AuthResult<String> {
        let claims = self.verify_token(refresh_token, "refresh")?;

        let user_id = claims.sub.parse::<Uuid>().map_err(|e| {
            AuthError::ValidationFailed(format!("Invalid user ID in refresh token: {}", e))
        })?;

        self.generate_access_token(user_id, &claims.email, &claims.role)
    }
}
