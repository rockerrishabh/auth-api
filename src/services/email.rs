use lettre::{
    message::{header::ContentType, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use serde::{Deserialize, Serialize};
use std::fs;
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

        // Load HTML templates
        tera.add_raw_template(
            "email_verification_otp",
            &fs::read_to_string("templates/email_verification.html").map_err(|e| {
                AuthError::InternalError(format!(
                    "Failed to load email verification template: {}",
                    e
                ))
            })?,
        )
        .map_err(|e| AuthError::InternalError(format!("Template engine error: {}", e)))?;

        tera.add_raw_template(
            "welcome_email",
            &fs::read_to_string("templates/welcome_email.html").map_err(|e| {
                AuthError::InternalError(format!("Failed to load welcome email template: {}", e))
            })?,
        )
        .map_err(|e| AuthError::InternalError(format!("Template engine error: {}", e)))?;

        tera.add_raw_template(
            "password_reset_email",
            &fs::read_to_string("templates/password_reset_email.html").map_err(|e| {
                AuthError::InternalError(format!("Failed to load password reset template: {}", e))
            })?,
        )
        .map_err(|e| AuthError::InternalError(format!("Template engine error: {}", e)))?;

        tera.add_raw_template(
            "security_alert_email",
            &fs::read_to_string("templates/security_alert.html").map_err(|e| {
                AuthError::InternalError(format!("Failed to load security alert template: {}", e))
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
            .render("email_verification_otp", &context)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_service_creation() {
        let config = EmailConfig {
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_username: "test@example.com".to_string(),
            smtp_password: "password".to_string(),
            from_email: "noreply@example.com".to_string(),
            from_name: "Test Service".to_string(),
        };

        let result = EmailService::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_otp_email() {
        let config = EmailConfig {
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_username: "test@example.com".to_string(),
            smtp_password: "password".to_string(),
            from_email: "noreply@example.com".to_string(),
            from_name: "Test Service".to_string(),
        };

        let email_service = EmailService::new(config).unwrap();
        // Note: This test doesn't actually send emails, just tests the service creation
        assert!(email_service
            .templates
            .get_template("email_verification_otp")
            .is_ok());
    }
}
