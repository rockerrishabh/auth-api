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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_config() -> JwtConfig {
        JwtConfig {
            secret: "test-secret-key-for-jwt-service-testing".to_string(),
            access_token_expiry: 3600,     // 1 hour
            refresh_token_expiry: 2592000, // 30 days
        }
    }

    #[test]
    fn test_jwt_service_creation() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config);
        assert!(jwt_service.is_ok());
    }

    #[test]
    fn test_generate_access_token() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config).unwrap();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token = jwt_service.generate_access_token(user_id, email, role);
        assert!(token.is_ok());
    }

    #[test]
    fn test_generate_refresh_token() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config).unwrap();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token = jwt_service.generate_refresh_token(user_id, email, role);
        assert!(token.is_ok());
    }

    #[test]
    fn test_generate_token_pair() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config).unwrap();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token_pair = jwt_service.generate_token_pair(user_id, email, role);
        assert!(token_pair.is_ok());

        let token_pair = token_pair.unwrap();
        assert!(!token_pair.access_token.is_empty());
        assert!(!token_pair.refresh_token.is_empty());
        assert_eq!(token_pair.token_type, "Bearer");
        assert_eq!(token_pair.expires_in, 3600);
    }

    #[test]
    fn test_verify_access_token() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config).unwrap();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token = jwt_service
            .generate_access_token(user_id, email, role)
            .unwrap();
        let claims = jwt_service.verify_access_token(&token);
        assert!(claims.is_ok());

        let claims = claims.unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.role, role);
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_verify_refresh_token() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config).unwrap();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token = jwt_service
            .generate_refresh_token(user_id, email, role)
            .unwrap();
        let claims = jwt_service.verify_refresh_token(&token);
        assert!(claims.is_ok());

        let claims = claims.unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.role, role);
        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_extract_user_id_from_token() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config).unwrap();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token = jwt_service
            .generate_access_token(user_id, email, role)
            .unwrap();
        let extracted_user_id = jwt_service.extract_user_id_from_token(&token, "access");
        assert!(extracted_user_id.is_ok());
        assert_eq!(extracted_user_id.unwrap(), user_id);
    }

    #[test]
    fn test_refresh_access_token() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config).unwrap();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let refresh_token = jwt_service
            .generate_refresh_token(user_id, email, role)
            .unwrap();
        let new_access_token = jwt_service.refresh_access_token(&refresh_token);
        assert!(new_access_token.is_ok());

        let new_access_token = new_access_token.unwrap();
        let claims = jwt_service.verify_access_token(&new_access_token);
        assert!(claims.is_ok());

        let claims = claims.unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.role, role);
        assert_eq!(claims.token_type, "access");
    }
}
