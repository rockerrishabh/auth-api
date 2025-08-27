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
