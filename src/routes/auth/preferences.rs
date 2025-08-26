use crate::{db::DbPool, services::UserService};
use actix_web::{get, put, web, HttpRequest, HttpResponse};
use validator::Validate;

#[derive(Debug, serde::Deserialize, Validate)]
pub struct UpdatePreferencesRequest {
    pub preferences: serde_json::Value,
}

#[derive(Debug, serde::Serialize)]
pub struct PreferencesResponse {
    pub message: String,
    pub success: bool,
    pub preferences: serde_json::Value,
}

/// Get user preferences
#[get("/preferences")]
pub async fn get_user_preferences(
    pool: web::Data<DbPool>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());

    // Get user details
    let user = user_service
        .get_user_by_id(user_id)
        .await?
        .ok_or(crate::error::AuthError::UserNotFound)?;

    Ok(HttpResponse::Ok().json(PreferencesResponse {
        message: "User preferences retrieved successfully".to_string(),
        success: true,
        preferences: user.preferences.unwrap_or_default(),
    }))
}

/// Update user preferences
#[put("/preferences")]
pub async fn update_user_preferences(
    pool: web::Data<DbPool>,
    req: web::Json<UpdatePreferencesRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, crate::error::AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let user_id = crate::middleware::extract_user_id_from_request(&http_req)
        .map_err(|_| crate::error::AuthError::InvalidToken)?;

    let user_service = UserService::new(pool.get_ref().clone());

    // Update user preferences
    let updated_user = user_service
        .update_user_preferences(user_id, req.preferences.clone())
        .await?;

    Ok(HttpResponse::Ok().json(PreferencesResponse {
        message: "User preferences updated successfully".to_string(),
        success: true,
        preferences: updated_user.preferences.unwrap_or_default(),
    }))
}
