use actix_multipart::Multipart;
use actix_web::{HttpResponse, Result, post, web::Data};
use diesel::{
    ExpressionMethods, RunQueryDsl, SelectableHelper,
    query_dsl::methods::{FilterDsl, SelectDsl},
};
use futures_util::{StreamExt as _, TryStreamExt};
use log::{error, info, warn};
use std::path::Path;
use thiserror::Error;

use crate::utils::image_process::{UploadConfig, image_process};
use crate::{
    db::{
        AppState,
        model::{NewEmailVerificationToken, NewUser, User},
        schema::{email_verification_tokens, users},
    },
    mail::{EmailConfig, send_message, templates::verification::verification_email},
    utils::{jwt::JwtConfig, password::PasswordService},
};

#[derive(Error, Debug)]
pub enum RegistrationError {
    #[error("Failed to read multipart form data: {0}")]
    MultipartError(#[from] actix_multipart::MultipartError),

    #[error("Invalid file type '{0}'. Allowed types: {1:?}")]
    InvalidFileType(String, Vec<String>),

    #[error("File '{0}' exceeds maximum size limit")]
    FileTooLarge(String),

    #[error("Image processing failed: {0}")]
    ImageProcessingError(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field data: {0}")]
    InvalidFieldData(String),

    #[error("Database connection failed")]
    DatabaseConnection,

    #[error("Database query failed: {0}")]
    DatabaseQuery(String),

    #[error("User with email '{0}' already exists")]
    UserAlreadyExists(String),

    #[error("Failed to create user: {0}")]
    UserCreationFailed(String),

    #[error("Failed to send verification email: {0}")]
    EmailSendFailed(String),
}

impl RegistrationError {
    pub fn to_http_response(&self) -> HttpResponse {
        match self {
            RegistrationError::MultipartError(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid form data",
                    "message": self.to_string()
                }))
            }
            RegistrationError::InvalidFileType(_, _)
            | RegistrationError::FileTooLarge(_)
            | RegistrationError::MissingField(_)
            | RegistrationError::InvalidFieldData(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Validation failed",
                    "message": self.to_string()
                }))
            }
            RegistrationError::UserAlreadyExists(_) => {
                HttpResponse::Conflict().json(serde_json::json!({
                    "error": "User already exists",
                    "message": self.to_string()
                }))
            }
            RegistrationError::DatabaseConnection
            | RegistrationError::DatabaseQuery(_)
            | RegistrationError::UserCreationFailed(_)
            | RegistrationError::ImageProcessingError(_)
            | RegistrationError::EmailSendFailed(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "An error occurred while processing your request"
                }))
            }
        }
    }
}

#[derive(Debug)]
struct RegistrationData {
    name: String,
    email: String,
    password: String,
    uploaded_files: Vec<crate::utils::image_process::ProcessedImage>,
}

#[derive(Debug)]
struct BufferedImageData {
    filename: String,
    data: Vec<u8>,
}

#[derive(Debug)]
struct ParsedFormData {
    name: String,
    email: String,
    password: String,
    buffered_images: Vec<BufferedImageData>,
}

impl ParsedFormData {
    fn new() -> Self {
        Self {
            name: String::new(),
            email: String::new(),
            password: String::new(),
            buffered_images: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), RegistrationError> {
        if self.name.trim().is_empty() {
            return Err(RegistrationError::MissingField("name".to_string()));
        }
        if self.email.trim().is_empty() {
            return Err(RegistrationError::MissingField("email".to_string()));
        }
        if self.password.is_empty() {
            return Err(RegistrationError::MissingField("password".to_string()));
        }

        // Basic email validation
        if !self.email.contains('@') || !self.email.contains('.') {
            return Err(RegistrationError::InvalidFieldData(
                "Invalid email format".to_string(),
            ));
        }

        // Password strength validation
        if self.password.len() < 6 {
            return Err(RegistrationError::InvalidFieldData(
                "Password must be at least 6 characters".to_string(),
            ));
        }

        Ok(())
    }
}

#[post("/register")]
pub async fn register_user(
    payload: Multipart,
    pool: Data<AppState>,
    email_config: Data<EmailConfig>,
    image_config: Data<UploadConfig>,
    jwt_config: Data<JwtConfig>,
) -> Result<HttpResponse> {
    info!("Registration endpoint called");

    match handle_registration(payload, pool, email_config, image_config, jwt_config).await {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Registration failed: {}", e);
            Ok(e.to_http_response())
        }
    }
}

async fn handle_registration(
    mut payload: Multipart,
    pool: Data<AppState>,
    email_config: Data<EmailConfig>,
    image_config: Data<UploadConfig>,
    jwt_config: Data<JwtConfig>,
) -> Result<HttpResponse, RegistrationError> {
    // Parse all form data but buffer images without processing them
    let parsed_data = parse_form_data_with_buffered_images(&mut payload, &image_config).await?;

    // Validate basic input data
    parsed_data.validate()?;

    info!(
        "Basic registration data validated for email: {}",
        parsed_data.email
    );

    // Get database connection early
    let mut conn = pool
        .db
        .get()
        .map_err(|_| RegistrationError::DatabaseConnection)?;

    // Check if user already exists BEFORE processing any images
    check_user_exists(&parsed_data.email, &mut conn).await?;

    // Only now process buffered images since we know the user doesn't exist
    let registration_data = process_buffered_images(parsed_data, &image_config).await?;

    // Create new user
    let user = create_user(&registration_data, &mut conn).await?;

    // Send verification email
    send_verification_email(&user, &email_config, &jwt_config, &mut conn).await?;

    info!("User registered successfully: {}", user.email);

    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "User registered successfully. Please check your email to verify your account.",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "avatar": user.avatar,
            "email_verified": user.email_verified
        }
    })))
}

async fn check_user_exists(
    email: &str,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
) -> Result<(), RegistrationError> {
    let existing_users = users::table
        .filter(users::dsl::email.eq(email))
        .select(User::as_select())
        .load::<User>(conn)
        .map_err(|e| RegistrationError::DatabaseQuery(e.to_string()))?;

    if !existing_users.is_empty() {
        return Err(RegistrationError::UserAlreadyExists(email.to_string()));
    }

    Ok(())
}

async fn create_user(
    data: &RegistrationData,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
) -> Result<User, RegistrationError> {
    // Hash the password
    let password_hash = PasswordService::hash_password(&data.password)
        .map_err(|e| RegistrationError::UserCreationFailed(e.to_string()))?;

    let avatar_url = format!(
        "https://api.stellerseller.store/static/{}",
        data.uploaded_files
            .first()
            .map(|f| f.avif_name.as_str())
            .unwrap_or("default.png"),
    );

    let new_user = NewUser {
        name: &data.name,
        email: &data.email,
        password_hash: Some(&password_hash),
        avatar: Some(&avatar_url),
        avatar_thumbnail: data
            .uploaded_files
            .first()
            .and_then(|f| f.thumbnail_name.as_deref()),
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning())
        .get_result::<User>(conn)
        .map_err(|e| RegistrationError::UserCreationFailed(e.to_string()))
}

async fn send_verification_email(
    user: &User,
    email_config: &EmailConfig,
    jwt_config: &JwtConfig,
    conn: &mut diesel::r2d2::PooledConnection<
        diesel::r2d2::ConnectionManager<diesel::PgConnection>,
    >,
) -> Result<(), RegistrationError> {
    // Generate JWT verification token
    let verification_token = jwt_config
        .generate_email_verification_token(user.id, &user.email)
        .map_err(|e| RegistrationError::EmailSendFailed(e.to_string()))?;

    // Hash the token before storing
    let token_hash = PasswordService::hash_password(&verification_token)
        .map_err(|e| RegistrationError::EmailSendFailed(e.to_string()))?;

    // Store the token in database
    let new_verification_token = NewEmailVerificationToken {
        user_id: user.id,
        token_hash: &token_hash,
        expires_at: chrono::Utc::now() + jwt_config.email_verification_expiry,
    };

    diesel::insert_into(email_verification_tokens::table)
        .values(&new_verification_token)
        .execute(conn)
        .map_err(|e| RegistrationError::EmailSendFailed(e.to_string()))?;

    // Send verification email
    let mail = verification_email(&user.name, &user.email, &verification_token);
    send_message(mail, email_config)
        .map_err(|e| RegistrationError::EmailSendFailed(e.to_string()))?;

    info!("Verification email sent to: {}", user.email);
    Ok(())
}

async fn parse_form_data_with_buffered_images(
    payload: &mut Multipart,
    image_config: &UploadConfig,
) -> Result<ParsedFormData, RegistrationError> {
    let mut data = ParsedFormData::new();

    while let Some(field_result) = payload.next().await {
        let mut field = field_result?;

        if let Some(cd) = field.content_disposition() {
            let field_name = cd.get_name().unwrap_or_default();
            let filename = cd.get_filename().map(|s| s.to_string());

            match field_name {
                "name" => {
                    data.name = read_field_text(&mut field).await.map_err(|_| {
                        RegistrationError::InvalidFieldData("Failed to read name field".to_string())
                    })?;
                    info!("Parsed name field");
                }
                "email" => {
                    data.email = read_field_text(&mut field).await.map_err(|_| {
                        RegistrationError::InvalidFieldData(
                            "Failed to read email field".to_string(),
                        )
                    })?;
                    info!("Parsed email field");
                }
                "password" => {
                    data.password = read_field_text(&mut field).await.map_err(|_| {
                        RegistrationError::InvalidFieldData(
                            "Failed to read password field".to_string(),
                        )
                    })?;
                    info!("Parsed password field");
                }
                "image" => {
                    if let Some(fname) = filename {
                        // Buffer the image data without processing it
                        let buffered_image =
                            buffer_image_data(&mut field, &fname, image_config).await?;
                        data.buffered_images.push(buffered_image);
                        info!("Buffered image data: {}", fname);
                    }
                }
                _ => {
                    warn!("Ignoring unrecognized field: {}", field_name);
                    // Consume the field data
                    while let Some(_chunk) = field.try_next().await? {
                        // Just consume the data
                    }
                }
            }
        }
    }

    Ok(data)
}

async fn buffer_image_data(
    field: &mut actix_multipart::Field,
    filename: &str,
    image_config: &UploadConfig,
) -> Result<BufferedImageData, RegistrationError> {
    // Validate file extension early
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    if !image_config.allowed_extensions.contains(&ext) {
        return Err(RegistrationError::InvalidFileType(
            ext,
            image_config.allowed_extensions.clone(),
        ));
    }

    // Read and buffer file data with size validation
    let mut file_data = Vec::new();
    let mut file_size = 0usize;

    while let Some(chunk) = field.try_next().await? {
        file_size += chunk.len();

        if file_size > image_config.max_file_size {
            return Err(RegistrationError::FileTooLarge(filename.to_string()));
        }

        file_data.extend_from_slice(&chunk);
    }

    Ok(BufferedImageData {
        filename: filename.to_string(),
        data: file_data,
    })
}

async fn process_buffered_images(
    parsed_data: ParsedFormData,
    image_config: &UploadConfig,
) -> Result<RegistrationData, RegistrationError> {
    let mut registration_data = RegistrationData {
        name: parsed_data.name,
        email: parsed_data.email,
        password: parsed_data.password,
        uploaded_files: Vec::new(),
    };

    // Process each buffered image
    for buffered_image in parsed_data.buffered_images {
        info!("Processing buffered image: {}", buffered_image.filename);

        let processed_image = image_process(
            buffered_image.data,
            buffered_image.filename.clone(),
            image_config,
        )
        .await
        .map_err(|e| RegistrationError::ImageProcessingError(e.to_string()))?;

        registration_data.uploaded_files.push(processed_image);
        info!("Successfully processed image: {}", buffered_image.filename);
    }

    Ok(registration_data)
}

async fn read_field_text(field: &mut actix_multipart::Field) -> Result<String> {
    let mut data = Vec::new();

    while let Some(chunk_result) = field.next().await {
        let chunk = chunk_result.map_err(|e| {
            error!("Error reading field chunk: {}", e);
            actix_web::error::ErrorBadRequest("Failed to read form field")
        })?;

        data.extend_from_slice(&chunk);
    }

    let text = String::from_utf8(data)
        .map_err(|e| {
            error!("Invalid UTF-8 in form field: {}", e);
            actix_web::error::ErrorBadRequest("Invalid text encoding in form field")
        })?
        .trim()
        .to_string();

    Ok(text)
}
