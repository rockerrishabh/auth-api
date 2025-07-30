use chrono::DateTime;
use chrono::offset::Utc;
use diesel::Selectable;
use diesel::prelude::{Insertable, Queryable};
use uuid::Uuid;

use crate::db::schema::users;

#[derive(diesel_derive_enum::DbEnum, Debug)]
#[db_enum(existing_type_path = "crate::db::schema::sql_types::UserRole")]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Queryable, Debug, Selectable)]
#[diesel(table_name = crate::db::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
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

#[derive(Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub password_hash: Option<&'a str>,
}
