use chrono::DateTime;
use chrono::offset::Utc;
use diesel::Selectable;
use diesel::prelude::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::schema::{email_verification_tokens, password_reset_tokens, refresh_tokens, users};

#[derive(diesel_derive_enum::DbEnum, Debug, Clone, Serialize, Deserialize)]
#[db_enum(existing_type_path = "crate::db::schema::sql_types::UserRole")]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Clone)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub name: String,
    pub avatar: Option<String>,
    pub avatar_thumbnail: Option<String>,
    pub role: UserRole,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub password_hash: Option<&'a str>,
    pub avatar: Option<&'a str>,
    pub avatar_thumbnail: Option<&'a str>,
}

// Refresh Token Model
#[derive(Queryable, Debug, Selectable, Serialize, Deserialize)]
#[diesel(table_name = refresh_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Insertable)]
#[diesel(table_name = refresh_tokens)]
pub struct NewRefreshToken<'a> {
    pub user_id: Uuid,
    pub token_hash: &'a str,
    pub expires_at: DateTime<Utc>,
}

// Password Reset Token Model
#[derive(Queryable, Debug, Selectable, Serialize, Deserialize)]
#[diesel(table_name = password_reset_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Insertable)]
#[diesel(table_name = password_reset_tokens)]
pub struct NewPasswordResetToken<'a> {
    pub user_id: Uuid,
    pub token_hash: &'a str,
    pub expires_at: DateTime<Utc>,
}

// Email Verification Token Model
#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Clone)]
#[diesel(table_name = email_verification_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct EmailVerificationToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Insertable)]
#[diesel(table_name = email_verification_tokens)]
pub struct NewEmailVerificationToken<'a> {
    pub user_id: Uuid,
    pub token_hash: &'a str,
    pub expires_at: DateTime<Utc>,
}
