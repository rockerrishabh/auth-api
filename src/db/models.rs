use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_derive_enum::DbEnum;
use diesel_json::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::schemas::*;
use crate::services::core::user::UserResponse;

// Enum definitions using diesel_derive_enum v3
#[derive(Debug, Clone, Serialize, Deserialize, DbEnum, PartialEq)]
#[db_enum(existing_type_path = "crate::db::schemas::sql_types::UserRole")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    SuperAdmin,
    Admin,
    Moderator,
    User,
    Guest,
}

#[derive(Debug, Clone, Serialize, Deserialize, DbEnum, PartialEq)]
#[db_enum(existing_type_path = "crate::db::schemas::sql_types::AccountStatus")]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Active,
    Suspended,
    Banned,
    PendingVerification,
    Deactivated,
}

#[derive(Debug, Clone, Serialize, Deserialize, DbEnum)]
#[db_enum(existing_type_path = "crate::db::schemas::sql_types::OtpType")]
#[serde(rename_all = "lowercase")]
pub enum OtpType {
    EmailVerification,
    PasswordReset,
    LoginVerification,
    TwoFactor,
    PhoneVerification,
}

// User Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub name: String,
    pub role: UserRole,
    pub email_verified: bool,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub two_factor_enabled: bool,
    pub two_factor_secret: Option<String>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub account_status: AccountStatus,
    pub avatar: Option<String>,
    pub avatar_thumbnail: Option<String>,
    pub preferences: Option<Json<serde_json::Value>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub role: UserRole,
    pub account_status: AccountStatus,
}

// OTP Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = otps)]
pub struct Otp {
    pub id: Uuid,
    pub user_id: Uuid,
    pub otp_type: OtpType,
    pub code: String,
    pub expires_at: DateTime<Utc>,
    pub attempts_remaining: i32,
    pub max_attempts: i32,
    pub is_used: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = otps)]
pub struct NewOtp {
    pub user_id: Uuid,
    pub otp_type: OtpType,
    pub code: String,
    pub expires_at: DateTime<Utc>,
    pub attempts_remaining: i32,
    pub max_attempts: i32,
}

// Session Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = user_sessions)]
pub struct UserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_info: Option<Json<serde_json::Value>>,
    pub is_active: bool,
    pub last_activity: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = user_sessions)]
pub struct NewUserSession {
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_info: Option<Json<serde_json::Value>>,
}

// Activity Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = user_activity_logs)]
pub struct UserActivityLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub activity_type: String,
    pub description: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<Json<serde_json::Value>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = user_activity_logs)]
pub struct NewUserActivityLog {
    pub user_id: Uuid,
    pub activity_type: String,
    pub description: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<Json<serde_json::Value>>,
}

// Token Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = refresh_tokens)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub is_revoked: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = refresh_tokens)]
pub struct NewRefreshToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = password_reset_tokens)]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub is_used: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = password_reset_tokens)]
pub struct NewPasswordResetToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = email_verification_tokens)]
pub struct EmailVerificationToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub is_used: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = email_verification_tokens)]
pub struct NewEmailVerificationToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

// Role Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = user_roles)]
pub struct UserRoleDefinition {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Json<serde_json::Value>,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = user_roles)]
pub struct NewUserRoleDefinition {
    pub name: UserRole,
    pub description: Option<String>,
    pub permissions: Json<serde_json::Value>,
    pub is_default: bool,
}

// Permission Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = user_permissions)]
pub struct UserPermission {
    pub id: Uuid,
    pub user_id: Uuid,
    pub permission: String,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = user_permissions)]
pub struct NewUserPermission {
    pub user_id: Uuid,
    pub permission: String,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

// Role Assignment Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = user_role_assignments)]
pub struct UserRoleAssignment {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = user_role_assignments)]
pub struct NewUserRoleAssignment {
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub assigned_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

// Implementations
impl User {
    pub fn can_login(&self) -> bool {
        self.account_status == AccountStatus::Active && !self.is_locked()
    }

    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            locked_until > Utc::now()
        } else {
            false
        }
    }

    pub fn to_response(&self) -> UserResponse {
        UserResponse {
            id: self.id,
            username: self.username.clone(),
            email: self.email.clone(),
            role: format!("{:?}", self.role).to_lowercase(),
            email_verified_at: if self.email_verified {
                Some(self.updated_at)
            } else {
                None
            },
            phone: self.phone.clone(),
            phone_verified: self.phone_verified,
            two_factor_enabled: self.two_factor_enabled,
            last_login_at: self.last_login_at,
            last_login_ip: None,      // Not available in this model
            failed_login_attempts: 0, // Not available in this model
            locked_until: None,       // Not available in this model
            account_status: format!("{:?}", self.account_status).to_lowercase(),
            preferences: None, // Not available in this model
            avatar: self.avatar.clone(),
            avatar_thumbnail: self.avatar_thumbnail.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl NewUser {
    pub fn new(username: String, email: String, password_hash: String, name: String) -> Self {
        Self {
            username,
            email,
            password_hash,
            name,
            role: UserRole::User,
            account_status: AccountStatus::PendingVerification,
        }
    }
}

impl Otp {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn has_attempts_remaining(&self) -> bool {
        self.attempts_remaining > 0
    }

    pub fn is_valid(&self) -> bool {
        !self.is_used && !self.is_expired() && self.has_attempts_remaining()
    }

    pub fn decrement_attempts(&mut self) {
        if self.attempts_remaining > 0 {
            self.attempts_remaining -= 1;
        }
    }

    pub fn mark_as_used(&mut self) {
        self.is_used = true;
    }
}

impl NewOtp {
    pub fn new(
        user_id: Uuid,
        otp_type: OtpType,
        code: String,
        expires_at: DateTime<Utc>,
        max_attempts: i32,
    ) -> Self {
        Self {
            user_id,
            otp_type,
            code,
            expires_at,
            attempts_remaining: max_attempts,
            max_attempts,
        }
    }
}

// System Settings Models
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = system_settings)]
pub struct SystemSetting {
    pub id: Uuid,
    pub setting_key: String,
    pub setting_value: String,
    pub setting_type: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = system_settings)]
pub struct NewSystemSetting<'a> {
    pub setting_key: &'a str,
    pub setting_value: &'a str,
    pub setting_type: &'a str,
    pub description: Option<&'a str>,
}
