use chrono::{Duration, Utc};
use diesel::prelude::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::SecurityConfig,
    db::{models::*, schemas::*, DbPool},
    error::{AuthError, AuthResult},
};

// Use the models OtpType
use crate::db::models::OtpType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpData {
    pub id: Uuid,
    pub user_id: Uuid,
    pub otp_type: OtpType,
    pub code: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub attempts_remaining: u8,
    pub max_attempts: u8,
    pub is_used: bool,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpRequest {
    pub user_id: Uuid,
    pub otp_type: OtpType,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpVerificationRequest {
    pub user_id: Uuid,
    pub otp_type: OtpType,
    pub code: String,
}

pub struct OtpService {
    config: SecurityConfig,
    db_pool: DbPool,
}

impl OtpService {
    pub fn new(config: SecurityConfig, db_pool: DbPool) -> Self {
        Self { config, db_pool }
    }

    /// Generate a new OTP code
    pub fn generate_otp(&self, otp_type: &OtpType) -> String {
        match otp_type {
            OtpType::EmailVerification | OtpType::PasswordReset => {
                // 6-digit numeric OTP for email verification and 2FA
                self.generate_numeric_otp(6)
            }
            OtpType::LoginVerification => {
                // 6-digit numeric OTP for login verification
                self.generate_numeric_otp(6)
            }
            OtpType::TwoFactor => {
                // 6-digit numeric OTP for 2FA
                self.generate_numeric_otp(6)
            }
            OtpType::PhoneVerification => {
                // 4-digit numeric OTP for phone verification (easier to type on mobile)
                self.generate_numeric_otp(4)
            }
        }
    }

    /// Generate a numeric OTP of specified length
    pub fn generate_numeric_otp(&self, length: usize) -> String {
        let mut rng = rand::thread_rng();
        let mut otp = String::with_capacity(length);

        for _ in 0..length {
            let digit = rng.gen_range(0..10);
            otp.push_str(&digit.to_string());
        }

        otp
    }

    /// Generate alphanumeric OTP
    pub fn generate_alphanumeric_otp(&self, length: usize) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Get OTP expiry duration based on type
    pub fn get_otp_expiry_duration(&self, otp_type: &OtpType) -> Duration {
        match otp_type {
            OtpType::EmailVerification => Duration::minutes(15), // 15 minutes for email verification
            OtpType::PasswordReset => Duration::minutes(10),     // 10 minutes for password reset
            OtpType::LoginVerification => Duration::minutes(5),  // 5 minutes for login verification
            OtpType::TwoFactor => Duration::minutes(3),          // 3 minutes for 2FA
            OtpType::PhoneVerification => Duration::minutes(10), // 10 minutes for phone verification
        }
    }

    /// Get maximum attempts allowed for OTP verification
    pub fn get_max_attempts(&self, _otp_type: &OtpType) -> u8 {
        self.config.max_failed_attempts.min(255) as u8 // Use config value with bounds
    }

    /// Create OTP data structure
    pub fn create_otp_data(&self, user_id: Uuid, otp_type: OtpType, code: String) -> OtpData {
        let now = Utc::now();
        let expires_at = now + self.get_otp_expiry_duration(&otp_type);
        let max_attempts = self.get_max_attempts(&otp_type);

        OtpData {
            id: Uuid::new_v4(),
            user_id,
            otp_type,
            code,
            expires_at,
            attempts_remaining: max_attempts,
            max_attempts,
            is_used: false,
            created_at: now,
        }
    }

    /// Validate OTP format
    pub fn validate_otp_format(&self, code: &str, otp_type: &OtpType) -> AuthResult<()> {
        let min_length = match otp_type {
            OtpType::EmailVerification => 6,
            OtpType::PasswordReset => 8,
            OtpType::LoginVerification => 6,
            OtpType::TwoFactor => 6,
            OtpType::PhoneVerification => 4,
        };

        if code.len() < min_length {
            return Err(AuthError::ValidationFailed(format!(
                "OTP code must be at least {} characters long",
                min_length
            )));
        }

        if !code.chars().all(|c| c.is_alphanumeric()) {
            return Err(AuthError::ValidationFailed(
                "OTP code must contain only alphanumeric characters".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if OTP is expired
    pub fn is_otp_expired(&self, otp_data: &OtpData) -> bool {
        Utc::now() > otp_data.expires_at
    }

    /// Check if OTP has attempts remaining
    pub fn has_attempts_remaining(&self, otp_data: &OtpData) -> bool {
        otp_data.attempts_remaining > 0
    }

    /// Check if OTP is valid
    pub fn is_otp_valid(&self, otp_data: &OtpData) -> bool {
        !self.is_otp_expired(otp_data) && self.has_attempts_remaining(otp_data) && !otp_data.is_used
    }

    /// Decrement OTP attempts
    pub fn decrement_attempts(&self, otp_data: &mut OtpData) {
        if otp_data.attempts_remaining > 0 {
            otp_data.attempts_remaining -= 1;
        }
    }

    /// Mark OTP as used
    pub fn mark_as_used(&self, otp_data: &mut OtpData) {
        otp_data.is_used = true;
    }

    /// Generate a secure random OTP with mixed characters
    pub fn generate_secure_otp(&self, length: usize) -> String {
        let mut rng = rand::thread_rng();
        let mut otp = String::with_capacity(length);

        // Mix of uppercase letters and numbers, avoiding confusing characters
        let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();

        for _ in 0..length {
            let idx = rng.gen_range(0..chars.len());
            otp.push(chars[idx]);
        }

        otp
    }

    /// Format expiry time for display
    pub fn format_expiry_time(&self, otp_data: &OtpData) -> String {
        let now = Utc::now();
        let duration = otp_data.expires_at - now;

        if duration.num_minutes() > 0 {
            format!("{} minutes", duration.num_minutes())
        } else if duration.num_seconds() > 0 {
            format!("{} seconds", duration.num_seconds())
        } else {
            "Expired".to_string()
        }
    }

    /// Check if OTP is expiring soon
    pub fn is_otp_expiring_soon(&self, otp_data: &OtpData) -> bool {
        let now = Utc::now();
        let duration = otp_data.expires_at - now;
        duration.num_minutes() <= 2 // Expiring in 2 minutes or less
    }

    /// Get OTP security level
    pub fn get_otp_security_level(&self, otp_type: &OtpType) -> &'static str {
        match otp_type {
            OtpType::EmailVerification => "Medium",
            OtpType::PasswordReset => "High",
            OtpType::LoginVerification => "Medium",
            OtpType::TwoFactor => "High",
            OtpType::PhoneVerification => "Low",
        }
    }

    /// Store OTP in database
    pub async fn store_otp(&self, request: &OtpRequest) -> AuthResult<OtpData> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let code = self.generate_otp(&request.otp_type);
        let otp_data = self.create_otp_data(request.user_id, request.otp_type.clone(), code);

        let new_otp = NewOtp::new(
            request.user_id,
            request.otp_type.clone(),
            otp_data.code.clone(),
            otp_data.expires_at,
            otp_data.max_attempts as i32,
        );

        diesel::insert_into(otps::table)
            .values(&new_otp)
            .execute(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(otp_data)
    }

    /// Verify OTP from database
    pub async fn verify_otp(&self, request: &OtpVerificationRequest) -> AuthResult<bool> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Find the latest unused OTP for this user and type
        let otp_record = otps::table
            .filter(otps::user_id.eq(request.user_id))
            .filter(otps::otp_type.eq(&request.otp_type))
            .filter(otps::is_used.eq(false))
            .order(otps::created_at.desc())
            .first::<Otp>(&mut conn)
            .optional()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if let Some(otp) = otp_record {
            // Check if OTP has expired
            if otp.is_expired() {
                return Err(AuthError::OtpExpired);
            }

            // Check if attempts remaining
            if !otp.has_attempts_remaining() {
                return Err(AuthError::OtpMaxAttemptsExceeded);
            }

            // Check if already used
            if otp.is_used {
                return Err(AuthError::OtpAlreadyUsed);
            }

            // Verify code
            if otp.code == request.code {
                // Mark as used
                diesel::update(otps::table.filter(otps::id.eq(otp.id)))
                    .set(otps::is_used.eq(true))
                    .execute(&mut conn)
                    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

                Ok(true)
            } else {
                // Decrement attempts
                let new_attempts = (otp.attempts_remaining - 1).max(0);
                diesel::update(otps::table.filter(otps::id.eq(otp.id)))
                    .set(otps::attempts_remaining.eq(new_attempts as i32))
                    .execute(&mut conn)
                    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

                Ok(false)
            }
        } else {
            Err(AuthError::OtpNotFound)
        }
    }

    /// Validate OTP locally (without database operations)
    pub fn validate_otp_locally(&self, otp_data: &mut OtpData, code: &str) -> AuthResult<bool> {
        // Check if OTP is expired
        if self.is_otp_expired(otp_data) {
            return Err(AuthError::OtpExpired);
        }

        // Check if attempts remaining
        if !self.has_attempts_remaining(otp_data) {
            return Err(AuthError::OtpMaxAttemptsExceeded);
        }

        // Check if already used
        if otp_data.is_used {
            return Err(AuthError::OtpAlreadyUsed);
        }

        // Verify code
        if otp_data.code == code {
            // Mark as used
            self.mark_as_used(otp_data);
            Ok(true)
        } else {
            // Decrement attempts
            self.decrement_attempts(otp_data);
            Err(AuthError::OtpInvalid)
        }
    }

    /// Get OTP by ID
    pub async fn get_otp(&self, otp_id: Uuid) -> AuthResult<Option<OtpData>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let otp_record = otps::table
            .find(otp_id)
            .first::<Otp>(&mut conn)
            .optional()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match otp_record {
            Some(otp) => Ok(Some(OtpData {
                id: otp.id,
                user_id: otp.user_id,
                otp_type: otp.otp_type,
                code: otp.code,
                expires_at: otp.expires_at,
                attempts_remaining: otp.attempts_remaining as u8,
                max_attempts: otp.max_attempts as u8,
                is_used: otp.is_used,
                created_at: otp.created_at,
            })),
            None => Ok(None),
        }
    }

    /// Clean up expired OTPs
    pub async fn cleanup_expired_otps(&self) -> AuthResult<usize> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let now = Utc::now();

        let deleted_count = diesel::delete(
            otps::table
                .filter(otps::expires_at.lt(now))
                .or_filter(otps::is_used.eq(true)),
        )
        .execute(&mut conn)
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(deleted_count)
    }

    /// Clean up expired OTPs for a specific user
    pub async fn cleanup_expired_otps_for_user(&self, user_id: Uuid) -> AuthResult<usize> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let now = Utc::now();

        let deleted_count = diesel::delete(
            otps::table.filter(otps::user_id.eq(user_id)).filter(
                otps::expires_at
                    .lt(now)
                    .or(otps::is_used.eq(true))
                    .or(otps::attempts_remaining.le(0)),
            ),
        )
        .execute(&mut conn)
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(deleted_count)
    }
}
