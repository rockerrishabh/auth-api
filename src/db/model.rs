use chrono::DateTime;
use chrono::offset::Utc;
use diesel::prelude::Queryable;
use uuid::Uuid;

#[derive(diesel_derive_enum::DbEnum, Debug)]
#[db_enum(existing_type_path = "crate::db::schema::sql_types::UserRole")]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Queryable, Debug)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub name: String,
    pub role: UserRole,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}
