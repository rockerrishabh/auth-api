use crate::config::AppConfig;
use crate::db::model::UserRole;
use crate::db::{model::User, schema::users, AppState};
use actix_web::{delete, get, post, put, web, web::Data, HttpResponse, Result};
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct MakeAdminRequest {
    user_email: String,
    admin_secret: String,
}

#[derive(Debug, Serialize)]
pub struct MakeAdminResponse {
    message: String,
    user: User,
}

#[derive(Debug, Serialize)]
pub struct AdminError {
    error: String,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct AdminStats {
    total_users: i64,
    verified_users: i64,
    unverified_users: i64,
    admin_users: i64,
    regular_users: i64,
    recent_registrations: i64,
}

#[derive(Debug, Serialize)]
pub struct UserListResponse {
    users: Vec<User>,
    total: i64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    name: Option<String>,
    email: Option<String>,
    role: Option<String>,
    email_verified: Option<bool>,
}

// Make user admin (with secret)
#[post("/make-admin")]
pub async fn make_user_admin(
    data: web::Json<MakeAdminRequest>,
    pool: Data<AppState>,
    config: Data<AppConfig>,
) -> Result<HttpResponse> {
    // Check if the admin secret is correct
    if data.admin_secret != config.admin.secret {
        return Ok(HttpResponse::Forbidden().json(AdminError {
            error: "Invalid admin secret".to_string(),
            message: "You are not authorized to perform this action".to_string(),
        }));
    }

    let mut conn = pool.db.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database connection failed: {}", e))
    })?;

    // Find the user by email
    let user = users::table
        .select(User::as_select())
        .filter(users::email.eq(&data.user_email))
        .first::<User>(&mut conn)
        .map_err(|e| actix_web::error::ErrorNotFound(format!("User not found: {}", e)))?;

    // Update the user role to admin
    let updated_user = diesel::update(users::table)
        .filter(users::id.eq(user.id))
        .set(users::role.eq(UserRole::Admin))
        .returning(User::as_select())
        .get_result::<User>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to update user: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(MakeAdminResponse {
        message: "User role updated to admin successfully".to_string(),
        user: updated_user,
    }))
}

// Get admin statistics
#[get("/stats")]
pub async fn get_admin_stats(pool: Data<AppState>) -> Result<HttpResponse> {
    let mut conn = pool.db.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database connection failed: {}", e))
    })?;

    // Get total users
    let total_users = users::table
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to count users: {}", e))
        })?;

    // Get verified users
    let verified_users = users::table
        .filter(users::email_verified.eq(true))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to count verified users: {}",
                e
            ))
        })?;

    // Get unverified users
    let unverified_users = users::table
        .filter(users::email_verified.eq(false))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to count unverified users: {}",
                e
            ))
        })?;

    // Get admin users
    let admin_users = users::table
        .filter(users::role.eq(UserRole::Admin))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to count admin users: {}",
                e
            ))
        })?;

    // Get regular users
    let regular_users = users::table
        .filter(users::role.eq(UserRole::User))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to count regular users: {}",
                e
            ))
        })?;

    // Get recent registrations (last 7 days)
    let week_ago = Utc::now() - chrono::Duration::days(7);
    let recent_registrations = users::table
        .filter(users::created_at.gt(week_ago))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to count recent registrations: {}",
                e
            ))
        })?;

    let stats = AdminStats {
        total_users,
        verified_users,
        unverified_users,
        admin_users,
        regular_users,
        recent_registrations,
    };

    Ok(HttpResponse::Ok().json(stats))
}

// Get all users (paginated)
#[get("/users")]
pub async fn get_all_users(
    pool: Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> Result<HttpResponse> {
    let mut conn = pool.db.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database connection failed: {}", e))
    })?;

    let page = query
        .get("page")
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(1);
    let per_page = query
        .get("per_page")
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(20);
    let offset = (page - 1) * per_page;

    // Get total count
    let total = users::table
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to count users: {}", e))
        })?;

    // Get paginated users
    let users_list = users::table
        .order(users::created_at.desc())
        .offset(offset)
        .limit(per_page)
        .select(User::as_select())
        .load::<User>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to load users: {}", e))
        })?;

    let response = UserListResponse {
        users: users_list,
        total,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Update user
#[put("/users/{user_id}")]
pub async fn update_user(
    path: web::Path<String>,
    data: web::Json<UpdateUserRequest>,
    pool: Data<AppState>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    let mut conn = pool.db.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database connection failed: {}", e))
    })?;

    // Parse user_id to UUID
    let user_uuid = user_id
        .parse::<uuid::Uuid>()
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid user ID format"))?;

    // Update user
    let mut updated_user = None;

    if let Some(name) = &data.name {
        let user = diesel::update(users::table)
            .filter(users::id.eq(user_uuid))
            .set(users::name.eq(name))
            .returning(User::as_select())
            .get_result::<User>(&mut conn)
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Failed to update user name: {}",
                    e
                ))
            })?;
        updated_user = Some(user);
    }

    if let Some(email) = &data.email {
        let user = diesel::update(users::table)
            .filter(users::id.eq(user_uuid))
            .set(users::email.eq(email))
            .returning(User::as_select())
            .get_result::<User>(&mut conn)
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Failed to update user email: {}",
                    e
                ))
            })?;
        updated_user = Some(user);
    }

    if let Some(role_str) = &data.role {
        let role = match role_str.as_str() {
            "admin" => UserRole::Admin,
            "user" => UserRole::User,
            _ => {
                return Ok(HttpResponse::BadRequest().json(AdminError {
                    error: "Invalid role".to_string(),
                    message: "Role must be 'admin' or 'user'".to_string(),
                }))
            }
        };
        let user = diesel::update(users::table)
            .filter(users::id.eq(user_uuid))
            .set(users::role.eq(role))
            .returning(User::as_select())
            .get_result::<User>(&mut conn)
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Failed to update user role: {}",
                    e
                ))
            })?;
        updated_user = Some(user);
    }

    if let Some(email_verified) = &data.email_verified {
        let user = diesel::update(users::table)
            .filter(users::id.eq(user_uuid))
            .set(users::email_verified.eq(*email_verified))
            .returning(User::as_select())
            .get_result::<User>(&mut conn)
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Failed to update user verification: {}",
                    e
                ))
            })?;
        updated_user = Some(user);
    }

    let updated_user =
        updated_user.ok_or_else(|| actix_web::error::ErrorBadRequest("No fields to update"))?;

    Ok(HttpResponse::Ok().json(updated_user))
}

// Delete user
#[delete("/users/{user_id}")]
pub async fn delete_user(path: web::Path<String>, pool: Data<AppState>) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    let mut conn = pool.db.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database connection failed: {}", e))
    })?;

    // Parse user_id to UUID
    let user_uuid = user_id
        .parse::<uuid::Uuid>()
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid user ID format"))?;

    // Delete user
    let deleted_count = diesel::delete(users::table)
        .filter(users::id.eq(user_uuid))
        .execute(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to delete user: {}", e))
        })?;

    if deleted_count == 0 {
        return Ok(HttpResponse::NotFound().json(AdminError {
            error: "User not found".to_string(),
            message: "No user was found with the specified ID".to_string(),
        }));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "User deleted successfully"
    })))
}
