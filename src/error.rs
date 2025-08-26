use actix_multipart::MultipartError;
use actix_web::{error::ResponseError, HttpResponse};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub code: Option<String>,
}

#[derive(Debug)]
pub enum AuthError {
    // Authentication errors
    InvalidCredentials,
    AccountNotVerified,
    AccountLocked,
    TokenExpired,
    InvalidToken,
    InsufficientPermissions,
    UserNotFound,

    // Validation errors
    ValidationFailed(String),

    // Database errors
    DatabaseError(String),

    // OTP errors
    OtpExpired,             // OTP has expired
    OtpInvalid,             // Invalid OTP code
    OtpMaxAttemptsExceeded, // Too many OTP verification attempts
    OtpAlreadyUsed,         // OTP has already been used
    OtpNotFound,            // OTP not found in database

    // Service errors
    ServiceUnavailable, // Used for service availability checks
    InternalError(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::AccountNotVerified => write!(f, "Account not verified"),
            AuthError::AccountLocked => write!(f, "Account locked"),
            AuthError::TokenExpired => write!(f, "Token expired"),
            AuthError::InvalidToken => write!(f, "Invalid token"),
            AuthError::InsufficientPermissions => write!(f, "Insufficient permissions"),
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::ValidationFailed(msg) => write!(f, "Validation failed: {}", msg),
            AuthError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AuthError::OtpExpired => write!(f, "OTP expired"),
            AuthError::OtpInvalid => write!(f, "Invalid OTP"),
            AuthError::OtpMaxAttemptsExceeded => write!(f, "OTP max attempts exceeded"),
            AuthError::OtpAlreadyUsed => write!(f, "OTP already used"),
            AuthError::OtpNotFound => write!(f, "OTP not found"),
            AuthError::ServiceUnavailable => write!(f, "Service unavailable"),
            AuthError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        let error_response = ErrorResponse {
            error: match self {
                AuthError::InvalidCredentials => "invalid_credentials",
                AuthError::AccountNotVerified => "account_not_verified",
                AuthError::AccountLocked => "account_locked",
                AuthError::TokenExpired => "token_expired",
                AuthError::InvalidToken => "invalid_token",
                AuthError::InsufficientPermissions => "insufficient_permissions",
                AuthError::UserNotFound => "user_not_found",
                AuthError::ValidationFailed(_) => "validation_failed",
                AuthError::DatabaseError(_) => "database_error",
                AuthError::OtpExpired => "otp_expired",
                AuthError::OtpInvalid => "otp_invalid",
                AuthError::OtpMaxAttemptsExceeded => "otp_max_attempts_exceeded",
                AuthError::OtpAlreadyUsed => "otp_already_used",
                AuthError::OtpNotFound => "otp_not_found",
                AuthError::ServiceUnavailable => "service_unavailable",
                AuthError::InternalError(_) => "internal_error",
            }
            .to_string(),
            message: self.to_string(),
            code: None,
        };

        match self {
            AuthError::InvalidCredentials
            | AuthError::AccountNotVerified
            | AuthError::AccountLocked => HttpResponse::Unauthorized().json(error_response),
            AuthError::TokenExpired | AuthError::InvalidToken => {
                HttpResponse::Unauthorized().json(error_response)
            }
            AuthError::InsufficientPermissions => HttpResponse::Forbidden().json(error_response),
            AuthError::UserNotFound => HttpResponse::NotFound().json(error_response),
            AuthError::ValidationFailed(_) => HttpResponse::BadRequest().json(error_response),
            AuthError::OtpExpired
            | AuthError::OtpInvalid
            | AuthError::OtpMaxAttemptsExceeded
            | AuthError::OtpAlreadyUsed
            | AuthError::OtpNotFound => HttpResponse::BadRequest().json(error_response),
            AuthError::ServiceUnavailable => {
                HttpResponse::ServiceUnavailable().json(error_response)
            }
            _ => HttpResponse::InternalServerError().json(error_response),
        }
    }
}

pub type AuthResult<T> = Result<T, AuthError>;

impl From<diesel::result::Error> for AuthError {
    fn from(error: diesel::result::Error) -> Self {
        match error {
            diesel::result::Error::NotFound => {
                AuthError::InternalError("Record not found".to_string())
            }
            diesel::result::Error::DatabaseError(kind, _) => {
                if let diesel::result::DatabaseErrorKind::UniqueViolation = kind {
                    AuthError::ValidationFailed("Duplicate record".to_string())
                } else {
                    AuthError::DatabaseError(error.to_string())
                }
            }
            _ => AuthError::DatabaseError(error.to_string()),
        }
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(error: serde_json::Error) -> Self {
        AuthError::ValidationFailed(error.to_string())
    }
}

impl From<validator::ValidationErrors> for AuthError {
    fn from(error: validator::ValidationErrors) -> Self {
        AuthError::ValidationFailed(error.to_string())
    }
}

impl From<diesel::r2d2::Error> for AuthError {
    fn from(error: diesel::r2d2::Error) -> Self {
        AuthError::DatabaseError(format!("Connection pool error: {}", error))
    }
}

impl From<uuid::Error> for AuthError {
    fn from(error: uuid::Error) -> Self {
        AuthError::ValidationFailed(format!("Invalid UUID: {}", error))
    }
}

impl From<chrono::ParseError> for AuthError {
    fn from(error: chrono::ParseError) -> Self {
        AuthError::ValidationFailed(format!("Date parsing error: {}", error))
    }
}

impl From<std::io::Error> for AuthError {
    fn from(error: std::io::Error) -> Self {
        AuthError::InternalError(format!("IO error: {}", error))
    }
}

impl From<MultipartError> for AuthError {
    fn from(error: MultipartError) -> Self {
        AuthError::ValidationFailed(format!("Multipart error: {}", error))
    }
}
