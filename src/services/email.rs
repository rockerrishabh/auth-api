use lettre::{
    message::{header::ContentType, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tera::{Context, Tera};

use crate::{
    config::EmailConfig,
    error::{AuthError, AuthResult},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailRequest {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub html_body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailTemplateData {
    pub name: String,
    pub otp: String,
    pub expiry_minutes: i32,
}

pub struct EmailService {
    config: EmailConfig,
    transport: SmtpTransport,
    templates: Tera,
}

impl EmailService {
    /// Get the templates directory path, trying multiple strategies
    fn get_template_dir() -> AuthResult<PathBuf> {
        // Strategy 1: Try relative to current executable
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let template_dir = exe_dir.join("templates");
                if template_dir.exists() {
                    return Ok(template_dir);
                }
                // Try going up one level (for cases where exe is in target/debug/)
                let template_dir = exe_dir
                    .parent()
                    .and_then(|parent| parent.parent())
                    .map(|root| root.join("templates"))
                    .filter(|path| path.exists());
                if let Some(dir) = template_dir {
                    return Ok(dir);
                }
            }
        }

        // Strategy 2: Try relative to current working directory
        let cwd_template_dir = PathBuf::from("templates");
        if cwd_template_dir.exists() {
            return Ok(cwd_template_dir);
        }

        // Strategy 3: Try using CARGO_MANIFEST_DIR if available (development)
        if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let template_dir = PathBuf::from(manifest_dir).join("templates");
            if template_dir.exists() {
                return Ok(template_dir);
            }
        }

        // Strategy 4: Try common locations
        let common_locations = [
            "/app/templates",             // Docker containers
            "/usr/local/share/templates", // System installations
            "./templates",                // Current directory
            "../templates",               // Parent directory
        ];

        for location in &common_locations {
            let template_dir = PathBuf::from(location);
            if template_dir.exists() {
                return Ok(template_dir);
            }
        }

        Err(AuthError::InternalError(
            "Could not find templates directory. Please ensure templates are available."
                .to_string(),
        ))
    }

    pub fn new(config: EmailConfig) -> AuthResult<Self> {
        let transport = if config.smtp_port == 587 {
            let builder = SmtpTransport::starttls_relay(&config.smtp_host)
                .map_err(|e| AuthError::InternalError(format!("SMTP relay error: {}", e)))?;

            builder
                .port(config.smtp_port)
                .credentials(Credentials::new(
                    config.smtp_username.clone(),
                    config.smtp_password.clone(),
                ))
                .build()
        } else {
            let builder = SmtpTransport::relay(&config.smtp_host)
                .map_err(|e| AuthError::InternalError(format!("SMTP relay error: {}", e)))?;

            builder
                .port(config.smtp_port)
                .credentials(Credentials::new(
                    config.smtp_username.clone(),
                    config.smtp_password.clone(),
                ))
                .build()
        };

        let mut tera = Tera::default();

        // Get the template directory path
        let template_dir = Self::get_template_dir()?;

        // Load HTML templates using absolute paths
        let email_verification_path = template_dir.join("email_verification.html");
        tera.add_raw_template(
            "email_verification_otp",
            &fs::read_to_string(&email_verification_path).map_err(|e| {
                AuthError::InternalError(format!(
                    "Failed to load email verification template from {}: {}",
                    email_verification_path.display(),
                    e
                ))
            })?,
        )
        .map_err(|e| AuthError::InternalError(format!("Template engine error: {}", e)))?;

        let welcome_email_path = template_dir.join("welcome_email.html");
        tera.add_raw_template(
            "welcome_email",
            &fs::read_to_string(&welcome_email_path).map_err(|e| {
                AuthError::InternalError(format!(
                    "Failed to load welcome email template from {}: {}",
                    welcome_email_path.display(),
                    e
                ))
            })?,
        )
        .map_err(|e| AuthError::InternalError(format!("Template engine error: {}", e)))?;

        let password_reset_path = template_dir.join("password_reset_email.html");
        tera.add_raw_template(
            "password_reset_email",
            &fs::read_to_string(&password_reset_path).map_err(|e| {
                AuthError::InternalError(format!(
                    "Failed to load password reset template from {}: {}",
                    password_reset_path.display(),
                    e
                ))
            })?,
        )
        .map_err(|e| AuthError::InternalError(format!("Template engine error: {}", e)))?;

        let security_alert_path = template_dir.join("security_alert.html");
        tera.add_raw_template(
            "security_alert_email",
            &fs::read_to_string(&security_alert_path).map_err(|e| {
                AuthError::InternalError(format!(
                    "Failed to load security alert template from {}: {}",
                    security_alert_path.display(),
                    e
                ))
            })?,
        )
        .map_err(|e| AuthError::InternalError(format!("Template engine error: {}", e)))?;

        let two_factor_path = template_dir.join("two_factor_otp.html");
        tera.add_raw_template(
            "two_factor_otp",
            &fs::read_to_string(&two_factor_path).map_err(|e| {
                AuthError::InternalError(format!(
                    "Failed to load two-factor OTP template from {}: {}",
                    two_factor_path.display(),
                    e
                ))
            })?,
        )
        .map_err(|e| AuthError::InternalError(format!("Template engine error: {}", e)))?;

        Ok(Self {
            config,
            transport,
            templates: tera,
        })
    }

    pub async fn send_email(&self, request: EmailRequest) -> AuthResult<()> {
        let from = format!("{} <{}>", self.config.from_name, self.config.from_email)
            .parse()
            .map_err(|e| AuthError::InternalError(format!("Invalid from address: {}", e)))?;

        let to = request
            .to
            .parse()
            .map_err(|e| AuthError::InternalError(format!("Invalid to address: {}", e)))?;

        let email_builder = Message::builder()
            .from(from)
            .to(to)
            .subject(request.subject);

        let email = if let Some(html_body) = request.html_body {
            // Send multipart email with both HTML and plain text
            email_builder
                .multipart(
                    MultiPart::alternative()
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_PLAIN)
                                .body(request.body),
                        )
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_HTML)
                                .body(html_body),
                        ),
                )
                .map_err(|e| AuthError::InternalError(format!("Email build error: {}", e)))?
        } else {
            // Send plain text email
            email_builder
                .body(request.body)
                .map_err(|e| AuthError::InternalError(format!("Email build error: {}", e)))?
        };

        self.transport
            .send(&email)
            .map_err(|e| AuthError::InternalError(format!("Email send error: {}", e)))?;

        Ok(())
    }

    pub async fn send_otp_email(
        &self,
        to: &str,
        name: &str,
        otp: &str,
        expiry_minutes: i32,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("otp", otp);
        context.insert("expiry_minutes", &expiry_minutes);

        let html_body = self
            .templates
            .render("email_verification_otp", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nYour verification code is: {}\n\nThis code will expire in {} minutes.\n\nBest regards,\nThe Platform Team",
            name, otp, expiry_minutes
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Your Verification Code".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    pub async fn send_password_reset_email(
        &self,
        to: &str,
        name: &str,
        reset_token: &str,
        expiry_minutes: i32,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("reset_token", reset_token);
        context.insert("expiry_minutes", &expiry_minutes);

        let html_body = self
            .templates
            .render("password_reset_email", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nYour password reset code is: {}\n\nThis code will expire in {} minutes.\n\nIf you didn't request this reset, please ignore this email.\n\nBest regards,\nThe Security Team",
            name, reset_token, expiry_minutes
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Password Reset Request".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    pub async fn send_welcome_email(&self, to: &str, name: &str) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);

        let html_body = self
            .templates
            .render("welcome_email", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Welcome to our platform, {}!\n\nYour account has been created successfully.\n\nYou can now access your dashboard and use all platform features.\n\nBest regards,\nThe Platform Team",
            name
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Welcome to Our Platform!".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    pub async fn send_account_locked_email(
        &self,
        to: &str,
        name: &str,
        reason: &str,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("reason", reason);
        context.insert(
            "timestamp",
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        );

        let html_body = self
            .templates
            .render("security_alert_email", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nYour account has been locked due to: {}\n\nPlease contact support for assistance.\n\nBest regards,\nThe Security Team",
            name, reason
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Account Security Alert".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    pub async fn send_two_factor_email(&self, to: &str, name: &str, code: &str) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("otp", code);
        context.insert("expiry_minutes", &10); // 2FA codes typically expire in 10 minutes

        let html_body = self
            .templates
            .render("two_factor_otp", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nYour two-factor authentication code is: {}\n\nThis code will expire in 10 minutes.\n\nBest regards,\nThe Security Team",
            name, code
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Two-Factor Authentication Code".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    /// Send comprehensive two-factor authentication OTP email with device info
    pub async fn send_two_factor_otp_email(
        &self,
        to: &str,
        name: &str,
        otp_code: &str,
        expiry_minutes: i32,
        login_time: &str,
        ip_address: &str,
        location: &str,
        user_agent: &str,
        browser_info: &str,
        app_name: &str,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("otp_code", otp_code);
        context.insert("expiry_minutes", &expiry_minutes);
        context.insert("login_time", login_time);
        context.insert("ip_address", ip_address);
        context.insert("location", location);
        context.insert("user_agent", user_agent);
        context.insert("browser_info", browser_info);
        context.insert("app_name", app_name);

        let html_body = self
            .templates
            .render("two_factor_otp", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},

A login attempt was detected for your {} account.

Verification Code: {}
Expires in: {} minutes

Login Details:
Time: {}
IP Address: {}
Location: {}
Device: {}
Browser: {}

If this wasn't you, please secure your account immediately.

Best regards,
The {} Security Team",
            name,
            app_name,
            otp_code,
            expiry_minutes,
            login_time,
            ip_address,
            location,
            user_agent,
            browser_info,
            app_name
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: format!("{} - Two-Factor Authentication Code", app_name),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    pub async fn send_security_alert_email(
        &self,
        to: &str,
        name: &str,
        alert_type: &str,
        details: &str,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("alert_type", alert_type);
        context.insert("details", details);
        context.insert(
            "timestamp",
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        );

        let html_body = self
            .templates
            .render("security_alert_email", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nA security alert has been triggered: {}\n\nDetails: {}\n\nTime: {}\n\nIf this wasn't you, please change your password immediately.\n\nBest regards,\nThe Security Team",
            name, alert_type, details, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Security Alert".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    /// Send email verification link for registration
    pub async fn send_verification_link(
        &self,
        to: &str,
        name: &str,
        verification_url: &str,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("verification_url", verification_url);
        context.insert(
            "timestamp",
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        );

        let html_body = self
            .templates
            .render("email_verification_link", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nWelcome to our platform! Please verify your email by clicking the link below:\n\n{}\n\nThis link will expire in 24 hours.\n\nIf you didn't create an account, please ignore this email.\n\nBest regards,\nThe Platform Team",
            name, verification_url
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Verify Your Email Address".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    /// Test email service connection
    pub async fn test_connection(&self) -> AuthResult<()> {
        // Try to connect to the SMTP server without sending an email
        // This tests the basic connectivity and authentication
        match self.transport.test_connection() {
            Ok(_) => Ok(()),
            Err(e) => Err(AuthError::InternalError(format!(
                "SMTP connection test failed: {}",
                e
            ))),
        }
    }
}
