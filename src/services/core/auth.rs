use actix_web::HttpRequest;
use argon2::{Argon2, PasswordHasher};
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use validator::Validate;

use super::session::{SessionRequest, SessionService};
use crate::{
    config::AppConfig,
    db::{models::*, schemas::*, DbPool},
    error::{AuthError, AuthResult},
    services::{
        activity::ActivityService,
        core::{
            password::PasswordService,
            user::{UserResponse, UserService},
        },
        utils::{
            email::EmailService,
            jwt::JwtService,
            otp::{OtpRequest, OtpService},
        },
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, message = "Username must be at least 3 characters long"))]
    pub username: String,
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    pub password: String,
    #[validate(length(min = 2, message = "Name must be at least 2 characters long"))]
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub message: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 1, message = "Email or username is required"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    pub remember_me: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub message: String,
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub session_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorRequiredResponse {
    pub message: String,
    pub user: UserResponse,
    pub two_factor_required: bool,
    pub otp_sent: bool,
}

pub struct AuthService {
    db_pool: DbPool,
    jwt_service: JwtService,
    session_service: SessionService,
    activity_service: ActivityService,
    user_service: UserService,
    config: AppConfig,
}

impl AuthService {
    pub fn new(
        db_pool: DbPool,
        jwt_service: JwtService,
        session_service: SessionService,
        activity_service: ActivityService,
        user_service: UserService,
        config: AppConfig,
    ) -> Self {
        Self {
            db_pool,
            jwt_service,
            session_service,
            activity_service,
            user_service,
            config,
        }
    }

    pub async fn register(
        &self,
        request: RegisterRequest,
        http_req: &actix_web::HttpRequest,
    ) -> AuthResult<RegisterResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Check if user already exists
        let existing_user = users::table
            .filter(users::email.eq(&request.email))
            .or_filter(users::username.eq(&request.username))
            .first::<User>(&mut conn)
            .optional()?;

        if existing_user.is_some() {
            return Err(AuthError::ValidationFailed(
                "User already exists".to_string(),
            ));
        }

        // Hash password
        let password_hash = self.hash_password(&request.password)?;

        // Create new user
        let new_user = NewUser::new(request.username, request.email, password_hash, request.name);

        let user: User = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(&mut conn)?;

        // Extract real IP address and User-Agent from request
        let ip_address = extract_ip_address(http_req);
        let user_agent = extract_user_agent(http_req);

        // Log activity
        let activity_request = crate::services::activity::ActivityLogRequest {
            user_id: user.id,
            activity_type: "registration".to_string(),
            description: "User registered successfully".to_string(),
            ip_address: Some(ip_address),
            user_agent: Some(user_agent),
            metadata: None,
        };

        self.activity_service.log_activity(activity_request).await?;

        Ok(RegisterResponse {
            message: "User registered successfully".to_string(),
            user: user.to_response(),
        })
    }

    pub async fn login(
        &self,
        request: LoginRequest,
        http_req: &actix_web::HttpRequest,
    ) -> AuthResult<LoginResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Find user by email or username
        let user = users::table
            .filter(users::email.eq(&request.email))
            .or_filter(users::username.eq(&request.email))
            .first::<User>(&mut conn)?;

        // Check if email is verified (if email verification is required)
        if self
            .config
            .get_bool_setting("email_verification_required", true)
            .unwrap_or(true)
            && user.email_verified_at.is_none()
        {
            return Err(AuthError::AccountNotVerified);
        }

        // Check if account is already locked before password verification
        if !user.can_login() {
            // Update failed login attempts even for locked accounts
            self.user_service
                .update_user_failed_attempts(user.id, 1)
                .await?;
            return Err(AuthError::AccountLocked);
        }

        // Verify password
        if let Some(password_hash) = &user.password_hash {
            if !self.verify_password(&request.password, password_hash)? {
                // Update failed login attempts
                let new_attempts = user.failed_login_attempts + 1;
                self.user_service
                    .update_user_failed_attempts(user.id, 1)
                    .await?;

                // Check if account should be locked due to too many failed attempts
                if new_attempts >= self.config.security.max_failed_attempts as i32 {
                    let lock_until = Utc::now()
                        + chrono::Duration::seconds(self.config.security.lockout_duration as i64);
                    self.user_service
                        .lock_user_account(user.id, Some(lock_until))
                        .await?;

                    // Log account lockout activity
                    let activity_request = crate::services::activity::ActivityLogRequest {
                        user_id: user.id,
                        activity_type: "account_lockout".to_string(),
                        description: format!(
                            "Account locked due to {} failed login attempts",
                            new_attempts
                        ),
                        ip_address: Some(extract_ip_address(http_req)),
                        user_agent: Some(extract_user_agent(http_req)),
                        metadata: Some(serde_json::json!({
                            "failed_attempts": new_attempts,
                            "max_attempts": self.config.security.max_failed_attempts,
                            "lockout_duration_seconds": self.config.security.lockout_duration
                        })),
                    };

                    // Don't fail the login if activity logging fails
                    if let Err(e) = self.activity_service.log_activity(activity_request).await {
                        eprintln!("Failed to log account lockout activity: {:?}", e);
                    }
                }

                return Err(AuthError::InvalidCredentials);
            }
        } else {
            // Update failed login attempts for accounts without password
            self.user_service
                .update_user_failed_attempts(user.id, 1)
                .await?;
            return Err(AuthError::InvalidCredentials);
        }

        // Check if 2FA is required for user's role or if user has 2FA enabled
        let user_role = format!("{:?}", user.role).to_lowercase();
        let is_two_factor_required = self.config.is_two_factor_required_for_role(&user_role);

        // If 2FA is required for this role but not enabled, return error
        if is_two_factor_required && !user.two_factor_enabled {
            return Err(AuthError::ValidationFailed(
                "Two-factor authentication is required for your account role. Please enable 2FA first.".to_string()
            ));
        }

        if user.two_factor_enabled || is_two_factor_required {
            // Extract request information for the email
            let ip_address = extract_ip_address(http_req);
            let user_agent = extract_user_agent(http_req);
            let login_time = chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string();

            // Create and store OTP in database
            let otp_request = OtpRequest {
                user_id: user.id,
                otp_type: crate::db::models::OtpType::TwoFactor,
                email: Some(user.email.clone()),
                phone: None,
            };

            let otp_service = OtpService::new(self.config.security.clone(), self.db_pool.clone());
            let otp_data = otp_service.store_otp(&otp_request).await?;
            let otp_code = otp_data.code.clone();

            // Send 2FA OTP email
            match EmailService::new(self.config.email.clone()) {
                Ok(email_service) => {
                    if let Err(email_err) = email_service
                        .send_two_factor_otp_email(
                            &user.email,
                            &user.name,
                            &otp_code,
                            10, // 10 minutes expiry
                            &login_time,
                            &ip_address,
                            "Unknown", // Could be enhanced with geo IP lookup
                            &user_agent,
                            "Unknown Browser", // Could be enhanced with user agent parsing
                            &self.config.email.from_name,
                        )
                        .await
                    {
                        eprintln!("Failed to send 2FA email: {}", email_err);
                        // Continue with 2FA flow even if email fails
                        // User can still get OTP via API if needed
                    }
                }
                Err(email_init_err) => {
                    eprintln!("Failed to initialize email service: {}", email_init_err);
                    // Continue with 2FA flow - OTP is stored in database
                    // User can still complete 2FA via API if needed
                }
            }

            // Reset failed login attempts on successful password verification
            if user.failed_login_attempts > 0 {
                self.user_service
                    .reset_user_failed_attempts(user.id)
                    .await?;
            }

            // Log 2FA initiation activity
            let activity_request = crate::services::activity::ActivityLogRequest {
                user_id: user.id,
                activity_type: "2fa_initiated".to_string(),
                description: "Two-factor authentication initiated during login".to_string(),
                ip_address: Some(ip_address),
                user_agent: Some(user_agent),
                metadata: Some(serde_json::json!({
                    "otp_type": "email",
                    "otp_expires_at": otp_data.expires_at
                })),
            };

            let _ = self.activity_service.log_activity(activity_request).await;

            return Ok(LoginResponse {
                message: "Two-factor authentication required. Please check your email.".to_string(),
                user: user.to_response(),
                access_token: "".to_string(), // No token until 2FA is completed
                refresh_token: "".to_string(),
                expires_in: 0,
                session_token: "".to_string(),
            });
        }

        // Reset failed login attempts on successful login (no 2FA)
        if user.failed_login_attempts > 0 {
            self.user_service
                .reset_user_failed_attempts(user.id)
                .await?;
        }

        // Generate token pair using the unified method
        let token_pair = self.jwt_service.generate_token_pair(
            user.id,
            &user.email,
            &format!("{:?}", user.role).to_lowercase(),
        )?;

        // Extract real IP address and User-Agent from request
        let ip_address = extract_ip_address(http_req);
        let user_agent = extract_user_agent(http_req);

        // Update user's login information
        self.user_service
            .update_user_login_info(user.id, Some(ip_address.clone()), Some(chrono::Utc::now()))
            .await?;

        // Create session
        let session_request = SessionRequest {
            user_id: user.id,
            ip_address: ip_address.clone(),
            user_agent: user_agent.clone(),
            device_info: None,
        };

        let session = self.session_service.create_session(session_request).await?;

        // Log activity
        let activity_request = crate::services::activity::ActivityLogRequest {
            user_id: user.id,
            activity_type: "login".to_string(),
            description: "User logged in successfully".to_string(),
            ip_address: Some(ip_address),
            user_agent: Some(user_agent),
            metadata: None,
        };

        self.activity_service.log_activity(activity_request).await?;

        Ok(LoginResponse {
            message: "Login successful".to_string(),
            user: user.to_response(),
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            expires_in: token_pair.expires_in,
            session_token: session.session_token,
        })
    }

    fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = argon2::password_hash::SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::InternalError(format!("Password hashing failed: {}", e)))
            .map(|hash| hash.to_string())
    }

    fn verify_password(&self, password: &str, hash: &str) -> AuthResult<bool> {
        // Use the dedicated PasswordService for verification with custom argon2 config
        let password_service = PasswordService::new(self.config.clone());
        password_service.verify_password(password, hash)
    }
}

/// Extract real IP address from HTTP request
pub fn extract_ip_address(req: &HttpRequest) -> String {
    // Try X-Forwarded-For header first (for proxies/load balancers)
    if let Some(x_forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = x_forwarded_for.to_str() {
            // X-Forwarded-For can contain multiple IPs, take the first one
            if let Some(first_ip) = xff_str.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    // Try X-Real-IP header (commonly used by nginx)
    if let Some(x_real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = x_real_ip.to_str() {
            let ip = ip_str.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }

    // Fall back to connection info
    req.connection_info()
        .peer_addr()
        .unwrap_or("0.0.0.0")
        .to_string()
}

/// Extract User-Agent from HTTP request
pub fn extract_user_agent(req: &HttpRequest) -> String {
    req.headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or("Unknown")
        .to_string()
}
