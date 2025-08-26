use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    config::AppConfig,
    error::{AuthError, AuthResult},
};

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PasswordChangeRequest {
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    pub current_password: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    pub new_password: String,
    #[validate(must_match(
        other = "new_password",
        message = "Password confirmation does not match"
    ))]
    pub confirm_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PasswordResetRequest {
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    pub new_password: String,
    #[validate(must_match(
        other = "new_password",
        message = "Password confirmation does not match"
    ))]
    pub confirm_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrengthResult {
    pub score: i32,
    pub strength: PasswordStrength,
    pub has_uppercase: bool,
    pub has_lowercase: bool,
    pub has_digit: bool,
    pub has_special: bool,
    pub length: usize,
}

pub struct PasswordService {
    config: AppConfig,
}

impl PasswordService {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);

        // Use custom argon2 configuration from config
        let argon2 = Argon2::new(
            Algorithm::default(),
            Version::default(),
            Params::new(
                self.config.security.argon2_memory_cost,
                self.config.security.argon2_time_cost,
                self.config.security.argon2_parallelism,
                None,
            )
            .map_err(|e| AuthError::InternalError(format!("Argon2 params error: {}", e)))?,
        );

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::InternalError(format!("Password hashing error: {}", e)))
            .map(|hash| hash.to_string())
    }

    /// Verify password against hash
    pub fn verify_password(&self, password: &str, hash: &str) -> AuthResult<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::InternalError(format!("Hash parsing error: {}", e)))?;

        // Use custom argon2 configuration from config
        let argon2 = Argon2::new(
            Algorithm::default(),
            Version::default(),
            Params::new(
                self.config.security.argon2_memory_cost,
                self.config.security.argon2_time_cost,
                self.config.security.argon2_parallelism,
                None,
            )
            .map_err(|e| AuthError::InternalError(format!("Argon2 params error: {}", e)))?,
        );

        Ok(PasswordVerifier::verify_password(&argon2, password.as_bytes(), &parsed_hash).is_ok())
    }

    /// Validate password strength
    pub fn validate_password_strength(&self, password: &str) -> PasswordStrengthResult {
        let mut score = 0i32;
        let mut has_uppercase = false;
        let mut has_lowercase = false;
        let mut has_digit = false;
        let mut has_special = false;

        for ch in password.chars() {
            if ch.is_ascii_uppercase() {
                has_uppercase = true;
                score += 1;
            } else if ch.is_ascii_lowercase() {
                has_lowercase = true;
                score += 1;
            } else if ch.is_ascii_digit() {
                has_digit = true;
                score += 1;
            } else if !ch.is_ascii_alphanumeric() {
                has_special = true;
                score += 2;
            }
        }

        // Length bonus
        score += password.len() as i32;

        // Strength classification
        let strength = if score < 10 {
            PasswordStrength::VeryWeak
        } else if score < 20 {
            PasswordStrength::Weak
        } else if score < 30 {
            PasswordStrength::Medium
        } else {
            PasswordStrength::Strong
        };

        PasswordStrengthResult {
            score,
            strength,
            has_uppercase,
            has_lowercase,
            has_digit,
            has_special,
            length: password.len(),
        }
    }

    /// Generate secure password
    pub fn generate_secure_password(&self, length: usize) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                !@#$%^&*()_+-=[]{}|;:,.<>?";

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate memorable password
    pub fn generate_memorable_password(&self, word_count: usize) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        const WORDS: &[&str] = &[
            "apple",
            "banana",
            "cherry",
            "dragon",
            "eagle",
            "forest",
            "garden",
            "house",
            "island",
            "jungle",
            "knight",
            "lemon",
            "mountain",
            "ocean",
            "planet",
            "queen",
            "river",
            "sunset",
            "tiger",
            "umbrella",
            "village",
            "window",
            "xylophone",
            "yellow",
            "zebra",
            "adventure",
            "beautiful",
            "creative",
            "delicious",
            "excellent",
            "fantastic",
            "gorgeous",
            "happiness",
            "incredible",
            "joyful",
            "knowledge",
            "lovely",
            "magnificent",
            "natural",
            "outstanding",
            "peaceful",
            "quality",
            "remarkable",
            "spectacular",
            "terrific",
            "unique",
            "valuable",
            "wonderful",
            "extraordinary",
            "brilliant",
            "charming",
            "delightful",
        ];

        let mut password = String::new();
        for i in 0..word_count {
            if i > 0 {
                password.push_str("-");
            }
            let word = WORDS[rng.gen_range(0..WORDS.len())];
            password.push_str(word);
        }

        // Add some numbers and symbols
        password.push_str(&rng.gen_range(10..100).to_string());
        password.push_str("!");

        password
    }

    pub fn validate_password_change(
        &self,
        request: &PasswordChangeRequest,
        current_hash: &str,
    ) -> AuthResult<()> {
        // Validate the request
        request
            .validate()
            .map_err(|e| AuthError::ValidationFailed(e.to_string()))?;

        // Verify current password
        if !self.verify_password(&request.current_password, current_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        // Check password strength
        let strength_result = self.validate_password_strength(&request.new_password);
        if matches!(
            strength_result.strength,
            PasswordStrength::VeryWeak | PasswordStrength::Weak
        ) {
            return Err(AuthError::ValidationFailed(
                "Password is too weak. Please choose a stronger password.".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_password_reset(&self, request: &PasswordResetRequest) -> AuthResult<()> {
        // Validate the request
        request
            .validate()
            .map_err(|e| AuthError::ValidationFailed(e.to_string()))?;

        // Check password strength
        let strength_result = self.validate_password_strength(&request.new_password);
        if matches!(
            strength_result.strength,
            PasswordStrength::VeryWeak | PasswordStrength::Weak
        ) {
            return Err(AuthError::ValidationFailed(
                "Password is too weak. Please choose a stronger password.".to_string(),
            ));
        }

        Ok(())
    }

    pub fn hash_and_validate_password(&self, password: &str) -> AuthResult<String> {
        // Validate password strength first
        let strength_result = self.validate_password_strength(password);
        if matches!(
            strength_result.strength,
            PasswordStrength::VeryWeak | PasswordStrength::Weak
        ) {
            return Err(AuthError::ValidationFailed(
                "Password is too weak. Please choose a stronger password.".to_string(),
            ));
        }

        // Hash the password
        self.hash_password(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, SecurityConfig};

    fn create_test_config() -> AppConfig {
        AppConfig {
            host: "0.0.0.0".to_string(),
            port: 5000,
            environment: "test".to_string(),
            jwt: crate::config::JwtConfig {
                secret: "test_secret".to_string(),
                access_token_expiry: 3600,
                refresh_token_expiry: 86400,
            },
            security: SecurityConfig {
                argon2_memory_cost: 65536,
                argon2_time_cost: 3,
                argon2_parallelism: 1,
                session_timeout: 3600,
                max_failed_attempts: 5,
                lockout_duration: 900,
            },
            email: crate::config::EmailConfig {
                smtp_host: "smtp.test.com".to_string(),
                smtp_port: 587,
                smtp_username: "test@test.com".to_string(),
                smtp_password: "test_password".to_string(),
                from_email: "noreply@test.com".to_string(),
                from_name: "Test Service".to_string(),
            },
            database: crate::config::DatabaseConfig {
                url: "postgres://test_user:test_password@localhost:5432/test_db".to_string(),
                max_connections: 10,
                min_connections: 2,
                connect_timeout: 10,
                idle_timeout: 300,
                max_lifetime: 3600,
            },
            upload: crate::config::UploadConfig {
                dir: "uploads".to_string(),
                max_size: 10485760,
                image_max_width: 1920,
                image_max_height: 1080,
                image_quality: 75,
                generate_thumbnails: true,
                thumbnail_size: 300,
                allowed_types: vec!["jpeg".to_string(), "png".to_string()],
            },
            frontend_url: "http://localhost:3000".to_string(),
        }
    }

    #[test]
    fn test_password_service_creation() {
        let config = create_test_config();
        let _service = PasswordService::new(config);
        // Service creation should succeed without panicking
    }

    #[test]
    fn test_hash_and_verify_password() {
        let config = create_test_config();
        let service = PasswordService::new(config);
        let password = "test_password_123";

        let hash = service.hash_password(password).unwrap();
        assert_ne!(password, hash);

        let is_valid = service.verify_password(password, &hash).unwrap();
        assert!(is_valid);

        let is_invalid = service.verify_password("wrong_password", &hash).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_password_strength_validation() {
        let config = create_test_config();
        let service = PasswordService::new(config);

        // Test weak password
        let weak_password = "123";
        let result = service.validate_password_strength(weak_password);
        assert!(matches!(result.strength, PasswordStrength::VeryWeak));

        // Test strong password
        let strong_password = "StrongP@ssw0rd123!";
        let result = service.validate_password_strength(strong_password);
        assert!(matches!(result.strength, PasswordStrength::Strong));
        assert!(result.has_uppercase);
        assert!(result.has_lowercase);
        assert!(result.has_digit);
        assert!(result.has_special);
    }

    #[test]
    fn test_generate_secure_password() {
        let config = create_test_config();
        let service = PasswordService::new(config);

        // Try multiple times to generate a strong password
        let mut attempts = 0;
        let mut password = String::new();
        let mut strength = PasswordStrength::VeryWeak;

        while attempts < 10 && !matches!(strength, PasswordStrength::Strong) {
            password = service.generate_secure_password(16); // Use longer length for better strength
            let result = service.validate_password_strength(&password);
            strength = result.strength;
            attempts += 1;
        }

        assert_eq!(password.len(), 16);
        assert!(matches!(strength, PasswordStrength::Strong));
        assert!(
            attempts <= 10,
            "Failed to generate strong password after 10 attempts"
        );
    }

    #[test]
    fn test_generate_memorable_password() {
        let config = create_test_config();
        let service = PasswordService::new(config);
        let password = service.generate_memorable_password(3);
        assert!(!password.is_empty());
        assert!(password.len() > 10); // Should be reasonably long
    }

    #[test]
    fn test_password_change_validation() {
        let config = create_test_config();
        let service = PasswordService::new(config);
        let current_password = "old_password_123";
        let current_hash = service.hash_password(current_password).unwrap();

        let request = PasswordChangeRequest {
            current_password: current_password.to_string(),
            new_password: "new_strong_password_456!".to_string(),
            confirm_password: "new_strong_password_456!".to_string(),
        };

        let result = service.validate_password_change(&request, &current_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_reset_validation() {
        let config = create_test_config();
        let service = PasswordService::new(config);

        let request = PasswordResetRequest {
            new_password: "new_strong_password_456!".to_string(),
            confirm_password: "new_strong_password_456!".to_string(),
        };

        let result = service.validate_password_reset(&request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_and_validate_password() {
        let config = create_test_config();
        let service = PasswordService::new(config);
        let strong_password = "StrongP@ssw0rd123!";

        let hash = service.hash_and_validate_password(strong_password).unwrap();
        assert_ne!(strong_password, hash);

        let is_valid = service.verify_password(strong_password, &hash).unwrap();
        assert!(is_valid);
    }
}
