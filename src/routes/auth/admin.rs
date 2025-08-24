use crate::config::AppConfig;
use crate::db::model::UserRole;
use crate::db::{model::User, schema::users, AppState};
use actix_web::{post, web, web::Data, HttpRequest, HttpResponse, Result};
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

// Make user admin (with secret)
#[post("/make-admin")]
pub async fn make_user_admin(
    req: HttpRequest,
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
        .filter(users::email.eq(&data.user_email))
        .first::<User>(&mut conn)
        .map_err(|e| actix_web::error::ErrorNotFound(format!("User not found: {}", e)))?;

    // Update the user role to admin
    let updated_user = diesel::update(users::table)
        .filter(users::id.eq(user.id))
        .set(users::role.eq(UserRole::Admin))
        .returning(User::as_returning())
        .get_result::<User>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to update user: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(MakeAdminResponse {
        message: "User role updated to admin successfully".to_string(),
        user: updated_user,
    }))
}

// Helper function to verify admin token
fn verify_admin_token(req: &HttpRequest, config: &AppConfig) -> Result<uuid::Uuid> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(actix_web::error::ErrorUnauthorized(
            "Missing authorization header",
        ))?;

    let token_data = config
        .jwt
        .verify_token(auth_header)
        .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid token"))?;

    let user_id = token_data.claims.sub;

    Ok(user_id)
}
