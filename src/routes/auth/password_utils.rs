use crate::{error::AuthResult, services::core::password::PasswordService};
use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};

use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct ValidatePasswordRequest {
    #[validate(length(min = 1, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct GeneratePasswordRequest {
    #[validate(range(min = 8, max = 128))]
    pub length: usize,
}

#[derive(Debug, Serialize)]
pub struct PasswordValidationResponse {
    pub valid: bool,
    pub score: u8,
    pub feedback: Vec<String>,
    pub strength: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordGenerationResponse {
    pub password: String,
    pub length: usize,
    pub strength: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordUtilityResponse {
    pub message: String,
    pub success: bool,
}

#[post("/validate")]
pub async fn validate_password_strength(
    req: web::Json<ValidatePasswordRequest>,
    config: web::Data<crate::config::AppConfig>,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let password_service = PasswordService::new(config.get_ref().clone());
    let result = password_service.validate_password_strength(&req.password);

    Ok(HttpResponse::Ok().json(PasswordValidationResponse {
        valid: result.score >= 20,
        score: result.score as u8,
        feedback: vec![format!("Password strength: {:?}", result.strength)],
        strength: format!("{:?}", result.strength).to_lowercase(),
    }))
}

#[post("/generate")]
pub async fn generate_secure_password(
    req: web::Json<GeneratePasswordRequest>,
    config: web::Data<crate::config::AppConfig>,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let password_service = PasswordService::new(config.get_ref().clone());
    let password = password_service.generate_secure_password(req.length);

    // Validate the generated password
    let validation = password_service.validate_password_strength(&password);
    let length = password.len();

    Ok(HttpResponse::Ok().json(PasswordGenerationResponse {
        password: password.clone(),
        length,
        strength: format!("{:?}", validation.strength).to_lowercase(),
    }))
}

#[post("/hash")]
pub async fn hash_password(
    req: web::Json<ValidatePasswordRequest>,
    config: web::Data<crate::config::AppConfig>,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let password_service = PasswordService::new(config.get_ref().clone());
    let hash = password_service.hash_password(&req.password)?;

    Ok(HttpResponse::Ok().json(PasswordUtilityResponse {
        message: hash,
        success: true,
    }))
}

/// Hash and validate password in one step (uses hash_and_validate_password method)
#[post("/hash-and-validate")]
pub async fn hash_and_validate_password(
    req: web::Json<ValidatePasswordRequest>,
    config: web::Data<crate::config::AppConfig>,
) -> AuthResult<HttpResponse> {
    req.validate()
        .map_err(|e| crate::error::AuthError::ValidationFailed(e.to_string()))?;

    let password_service = PasswordService::new(config.get_ref().clone());

    // Use the hash_and_validate_password method to both hash and validate
    let hash = password_service.hash_and_validate_password(&req.password)?;

    Ok(HttpResponse::Ok().json(PasswordUtilityResponse {
        message: format!("Password hashed and validated successfully: {}", hash),
        success: true,
    }))
}
