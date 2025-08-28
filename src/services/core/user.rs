use crate::{
    db::{
        models::{AccountStatus, User, UserRole},
        DbPool,
    },
    error::{AuthError, AuthResult},
};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Import schema DSL
use crate::db::schemas::users;
use crate::db::schemas::users::dsl::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub username: String,
    pub role: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub two_factor_enabled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub account_status: String,
    pub preferences: Option<serde_json::Value>,
    pub avatar: Option<String>,
    pub avatar_thumbnail: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            name: user.name,
            email: user.email,
            username: user.username,
            role: format!("{:?}", user.role).to_lowercase(),
            email_verified_at: user.email_verified_at,
            phone: user.phone,
            phone_verified: user.phone_verified,
            two_factor_enabled: user.two_factor_enabled,
            last_login_at: user.last_login_at,
            last_login_ip: user.last_login_ip,
            failed_login_attempts: user.failed_login_attempts,
            locked_until: user.locked_until,
            account_status: format!("{:?}", user.account_status).to_lowercase(),
            preferences: user.preferences.map(|p| p.0),
            avatar: user.avatar,
            avatar_thumbnail: user.avatar_thumbnail,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListResponse {
    pub users: Vec<UserResponse>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

pub struct UserService {
    db_pool: DbPool,
}

impl UserService {
    pub fn new(db_pool: DbPool) -> Self {
        Self { db_pool }
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> AuthResult<Option<UserResponse>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let user = users
            .filter(id.eq(user_id))
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user.map(|u| u.into()))
    }

    pub async fn get_user_by_email(&self, target_email: &str) -> AuthResult<Option<UserResponse>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let user = users
            .filter(email.eq(target_email))
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user.map(|u| u.into()))
    }

    pub async fn get_user_by_username(
        &self,
        target_username: &str,
    ) -> AuthResult<Option<UserResponse>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let user = users
            .filter(username.eq(target_username))
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user.map(|u| u.into()))
    }

    pub async fn update_user_name(
        &self,
        user_id: Uuid,
        new_name: &str,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set(name.eq(new_name))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn update_user_email(
        &self,
        user_id: Uuid,
        new_email: &str,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Check if email already exists
        let existing_user = users
            .filter(email.eq(new_email))
            .filter(id.ne(user_id))
            .first::<User>(&mut conn)
            .optional()?;

        if existing_user.is_some() {
            return Err(AuthError::ValidationFailed(
                "Email already exists".to_string(),
            ));
        }

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set(email.eq(new_email))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn update_user_role(
        &self,
        user_id: Uuid,
        new_role: &str,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Parse the role string to UserRole enum
        let role_enum = match new_role.to_lowercase().as_str() {
            "super_admin" => UserRole::SuperAdmin,
            "admin" => UserRole::Admin,
            "moderator" => UserRole::Moderator,
            "user" => UserRole::User,
            "guest" => UserRole::Guest,
            _ => return Err(AuthError::ValidationFailed("Invalid role".to_string())),
        };

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set(role.eq(role_enum))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn update_user_phone(
        &self,
        user_id: Uuid,
        new_phone: &str,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set(phone.eq(new_phone))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn update_user_preferences(
        &self,
        user_id: Uuid,
        new_preferences: serde_json::Value,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set(preferences.eq(diesel_json::Json(new_preferences)))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn update_user_status(
        &self,
        user_id: Uuid,
        new_status: &str,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Parse the status string to AccountStatus enum
        let status_enum = match new_status.to_lowercase().as_str() {
            "active" => AccountStatus::Active,
            "suspended" => AccountStatus::Suspended,
            "banned" => AccountStatus::Banned,
            "pending_verification" => AccountStatus::PendingVerification,
            "deactivated" => AccountStatus::Deactivated,
            _ => {
                return Err(AuthError::ValidationFailed(
                    "Invalid account status".to_string(),
                ))
            }
        };

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set(account_status.eq(status_enum))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    /// Update user locked status
    pub async fn update_user_locked_status(
        &self,
        user_id: Uuid,
        new_locked_until: Option<DateTime<Utc>>,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set(locked_until.eq(new_locked_until))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    /// Update user failed login attempts
    pub async fn update_user_failed_attempts(
        &self,
        user_id: Uuid,
        increment_by: i32,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // First get the current user to see the current failed attempts
        let current_user = users::table
            .filter(users::id.eq(user_id))
            .first::<User>(&mut conn)?;

        let new_attempts = current_user.failed_login_attempts + increment_by;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set(failed_login_attempts.eq(new_attempts))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    /// Update user login information
    pub async fn update_user_login_info(
        &self,
        user_id: Uuid,
        login_ip: Option<String>,
        login_time: Option<DateTime<Utc>>,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set((
                last_login_ip.eq(login_ip),
                last_login_at.eq(login_time),
                updated_at.eq(Utc::now()),
            ))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn update_user_two_factor(
        &self,
        user_id: Uuid,
        enabled: bool,
        secret: Option<String>,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set((two_factor_enabled.eq(enabled), two_factor_secret.eq(secret)))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn update_user_verification(
        &self,
        user_id: Uuid,
        new_email_verified: Option<DateTime<Utc>>,
        new_phone_verified: Option<bool>,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Use conditional updates based on what's provided
        let updated_user =
            if let (Some(verified_at), Some(verified)) = (new_email_verified, new_phone_verified) {
                diesel::update(users.filter(id.eq(user_id)))
                    .set((
                        email_verified_at.eq(Some(verified_at)),
                        phone_verified.eq(verified),
                    ))
                    .get_result::<User>(&mut conn)?
            } else if let Some(verified_at) = new_email_verified {
                diesel::update(users.filter(id.eq(user_id)))
                    .set(email_verified_at.eq(Some(verified_at)))
                    .get_result::<User>(&mut conn)?
            } else if let Some(verified) = new_phone_verified {
                diesel::update(users.filter(id.eq(user_id)))
                    .set(phone_verified.eq(verified))
                    .get_result::<User>(&mut conn)?
            } else {
                return Err(AuthError::ValidationFailed(
                    "No updates provided".to_string(),
                ));
            };

        Ok(updated_user.into())
    }

    /// Update user password
    pub async fn update_user_password(
        &self,
        user_id: Uuid,
        hashed_password: &str,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set((
                password_hash.eq(Some(hashed_password.to_string())),
                updated_at.eq(Utc::now()),
            ))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    /// Update user avatar
    pub async fn update_user_avatar(
        &self,
        user_id: Uuid,
        avatar_url: &str,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set((
                avatar.eq(Some(avatar_url.to_string())),
                updated_at.eq(Utc::now()),
            ))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn update_user_avatar_thumbnail(
        &self,
        user_id: Uuid,
        thumbnail_url: &str,
    ) -> AuthResult<UserResponse> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let updated_user = diesel::update(users.filter(id.eq(user_id)))
            .set((
                avatar_thumbnail.eq(Some(thumbnail_url.to_string())),
                updated_at.eq(Utc::now()),
            ))
            .get_result::<User>(&mut conn)?;

        Ok(updated_user.into())
    }

    pub async fn list_users(
        &self,
        page: Option<i64>,
        per_page: Option<i64>,
        role_filter: Option<&str>,
        status_filter: Option<&str>,
    ) -> AuthResult<(Vec<UserResponse>, i64)> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let mut query = users.into_boxed();

        if let Some(role_str) = role_filter {
            let role_enum = match role_str.to_lowercase().as_str() {
                "super_admin" => UserRole::SuperAdmin,
                "admin" => UserRole::Admin,
                "moderator" => UserRole::Moderator,
                "user" => UserRole::User,
                "guest" => UserRole::Guest,
                _ => {
                    return Err(AuthError::ValidationFailed(
                        "Invalid role filter".to_string(),
                    ))
                }
            };
            query = query.filter(role.eq(role_enum));
        }

        if let Some(status_str) = status_filter {
            let status_enum = match status_str.to_lowercase().as_str() {
                "active" => AccountStatus::Active,
                "suspended" => AccountStatus::Suspended,
                "banned" => AccountStatus::Banned,
                "pending_verification" => AccountStatus::PendingVerification,
                "deactivated" => AccountStatus::Deactivated,
                _ => {
                    return Err(AuthError::ValidationFailed(
                        "Invalid status filter".to_string(),
                    ))
                }
            };
            query = query.filter(account_status.eq(status_enum));
        }

        let total = query.count().get_result::<i64>(&mut conn)?;

        let page = page.unwrap_or(1);
        let per_page = per_page.unwrap_or(10);
        let offset = (page - 1) * per_page;

        let users_list = users
            .order(created_at.desc())
            .offset(offset)
            .limit(per_page)
            .load::<User>(&mut conn)?;

        Ok((users_list.into_iter().map(|u| u.into()).collect(), total))
    }

    pub async fn delete_user(&self, user_id: Uuid) -> AuthResult<bool> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let deleted = diesel::delete(users.filter(id.eq(user_id))).execute(&mut conn)?;

        Ok(deleted > 0)
    }

    pub async fn search_users(&self, search_term: &str) -> AuthResult<Vec<UserResponse>> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let search_pattern = format!("%{}%", search_term);

        let users_list = users
            .filter(
                email
                    .like(&search_pattern)
                    .or(username.like(&search_pattern))
                    .or(phone.like(&search_pattern)),
            )
            .order(created_at.desc())
            .limit(50)
            .load::<User>(&mut conn)?;

        Ok(users_list.into_iter().map(|u| u.into()).collect())
    }

    /// Advanced user search with filters (used by admin routes)
    pub async fn advanced_user_search(
        &self,
        search_term: Option<&str>,
        role_filter: Option<&str>,
        status_filter: Option<&str>,
        email_verified_filter: Option<bool>,
        two_factor_enabled_filter: Option<bool>,
        page: i64,
        per_page: i64,
        sort_by: &str,
        sort_order: &str,
    ) -> AuthResult<(Vec<UserResponse>, i64)> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Build query with all filters
        let mut query = users::table.into_boxed::<diesel::pg::Pg>();

        // Apply search term filter
        query = if let Some(term) = search_term {
            let search_pattern = format!("%{}%", term);
            query.filter(
                email
                    .like(search_pattern.clone())
                    .or(username.like(search_pattern.clone()))
                    .or(phone.like(search_pattern)),
            )
        } else {
            query
        };

        // Apply role filter
        query = if let Some(role_value) = role_filter {
            if let Some(role_enum) = match role_value.to_lowercase().as_str() {
                "super_admin" => Some(crate::db::models::UserRole::SuperAdmin),
                "admin" => Some(crate::db::models::UserRole::Admin),
                "moderator" => Some(crate::db::models::UserRole::Moderator),
                "user" => Some(crate::db::models::UserRole::User),
                "guest" => Some(crate::db::models::UserRole::Guest),
                _ => None,
            } {
                query.filter(role.eq(role_enum))
            } else {
                query
            }
        } else {
            query
        };

        // Apply status filter
        query = if let Some(status) = status_filter {
            match status {
                "active" => {
                    query.filter(account_status.eq(crate::db::models::AccountStatus::Active))
                }
                "suspended" => {
                    query.filter(account_status.eq(crate::db::models::AccountStatus::Suspended))
                }
                "banned" => {
                    query.filter(account_status.eq(crate::db::models::AccountStatus::Banned))
                }
                "pending" => query.filter(
                    account_status.eq(crate::db::models::AccountStatus::PendingVerification),
                ),
                "deactivated" => {
                    query.filter(account_status.eq(crate::db::models::AccountStatus::Deactivated))
                }
                _ => query,
            }
        } else {
            query
        };

        // Apply email verification filter
        query = if let Some(verified) = email_verified_filter {
            if verified {
                query.filter(email_verified_at.is_not_null())
            } else {
                query.filter(email_verified_at.is_null())
            }
        } else {
            query
        };

        // Apply 2FA filter
        query = if let Some(enabled) = two_factor_enabled_filter {
            query.filter(two_factor_enabled.eq(enabled))
        } else {
            query
        };

        // Get total count for pagination
        let total_query = users::table.into_boxed::<diesel::pg::Pg>();
        let total = total_query.count().get_result::<i64>(&mut conn)?;

        // Apply sorting
        match sort_by {
            "username" => {
                if sort_order == "asc" {
                    query = query.order(username.asc());
                } else {
                    query = query.order(username.desc());
                }
            }
            "email" => {
                if sort_order == "asc" {
                    query = query.order(email.asc());
                } else {
                    query = query.order(email.desc());
                }
            }
            "created_at" | _ => {
                if sort_order == "asc" {
                    query = query.order(created_at.asc());
                } else {
                    query = query.order(created_at.desc());
                }
            }
        }

        // Apply pagination
        let offset = (page - 1) * per_page;
        let users_list = query
            .offset(offset)
            .limit(per_page)
            .load::<User>(&mut conn)?;

        Ok((users_list.into_iter().map(|u| u.into()).collect(), total))
    }

    /// Get total user count
    pub async fn get_total_user_count(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = users.count().get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get active user count
    pub async fn get_active_user_count(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = users
            .filter(account_status.eq(AccountStatus::Active))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get verified user count
    pub async fn get_verified_user_count(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = users
            .filter(email_verified_at.is_not_null())
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get users with 2FA enabled count
    pub async fn get_users_with_2fa_count(&self) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let count = users
            .filter(two_factor_enabled.eq(true))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get recent registrations count
    pub async fn get_recent_registrations_count(&self, days: i64) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let days_ago = Utc::now() - chrono::Duration::days(days);
        let count = users
            .filter(created_at.gt(days_ago))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Get users count by role
    pub async fn get_users_by_role_count(&self, role_name: &str) -> AuthResult<i64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Parse the role string to UserRole enum
        let role_enum = match role_name.to_lowercase().as_str() {
            "super_admin" => UserRole::SuperAdmin,
            "admin" => UserRole::Admin,
            "moderator" => UserRole::Moderator,
            "user" => UserRole::User,
            "guest" => UserRole::Guest,
            _ => return Err(AuthError::ValidationFailed("Invalid role".to_string())),
        };

        let count = users
            .filter(role.eq(role_enum))
            .count()
            .get_result::<i64>(&mut conn)?;

        Ok(count)
    }

    /// Export users data to CSV format
    pub async fn export_users_csv(&self, include_sensitive: bool) -> AuthResult<String> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let all_users = users.load::<User>(&mut conn)?;

        let mut csv_data = String::new();

        // CSV header
        if include_sensitive {
            csv_data.push_str("ID,Username,Email,Name,Role,Email Verified,Phone,Phone Verified,2FA Enabled,Account Status,Last Login,Last Login IP,Failed Attempts,Locked Until,Created At,Updated At\n");
        } else {
            csv_data.push_str("ID,Username,Email,Name,Role,Email Verified,Phone Verified,2FA Enabled,Account Status,Last Login,Created At,Updated At\n");
        }

        // CSV rows
        for user in all_users {
            let row = if include_sensitive {
                format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    user.id,
                    user.username,
                    user.email,
                    user.name,
                    format!("{:?}", user.role).to_lowercase(),
                    user.email_verified_at
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default(),
                    user.phone.unwrap_or_default(),
                    user.phone_verified,
                    user.two_factor_enabled,
                    format!("{:?}", user.account_status).to_lowercase(),
                    user.last_login_at
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default(),
                    user.last_login_ip.unwrap_or_default(),
                    user.failed_login_attempts,
                    user.locked_until
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default(),
                    user.created_at.to_rfc3339(),
                    user.updated_at.to_rfc3339(),
                )
            } else {
                format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    user.id,
                    user.username,
                    user.email,
                    user.name,
                    format!("{:?}", user.role).to_lowercase(),
                    user.email_verified_at
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default(),
                    user.phone_verified,
                    user.two_factor_enabled,
                    format!("{:?}", user.account_status).to_lowercase(),
                    user.last_login_at
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default(),
                    user.created_at.to_rfc3339(),
                    user.updated_at.to_rfc3339(),
                )
            };
            csv_data.push_str(&row);
        }

        Ok(csv_data)
    }

    /// Reset failed login attempts for a user (on successful login)
    pub async fn reset_user_failed_attempts(&self, user_id: Uuid) -> AuthResult<()> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set((
                users::failed_login_attempts.eq(0),
                users::locked_until.eq(None::<DateTime<Utc>>),
                users::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Lock user account until specified time
    pub async fn lock_user_account(
        &self,
        user_id: Uuid,
        lock_until: Option<DateTime<Utc>>,
    ) -> AuthResult<()> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set((
                users::locked_until.eq(lock_until),
                users::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Unlock user account and reset failed login attempts
    pub async fn unlock_user_account(&self, user_id: Uuid) -> AuthResult<()> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set((
                users::locked_until.eq(None::<DateTime<Utc>>),
                users::failed_login_attempts.eq(0),
                users::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Force unlock all accounts that are past their lockout duration
    pub async fn unlock_expired_accounts(&self) -> AuthResult<u64> {
        let mut conn = self
            .db_pool
            .get()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let now = Utc::now();
        let result = diesel::update(users::table.filter(users::locked_until.lt(now)))
            .set((
                users::locked_until.eq(None::<DateTime<Utc>>),
                users::failed_login_attempts.eq(0),
                users::updated_at.eq(now),
            ))
            .execute(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(result as u64)
    }
}
