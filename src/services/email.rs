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
            "email_verification",
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

        tera.add_raw_template(
            "two_factor_otp",
            &fs::read_to_string("templates/two_factor_otp.html").map_err(|e| {
                AuthError::InternalError(format!("Failed to load two-factor OTP template: {}", e))
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

    pub async fn send_otp_email_with_details(
        &self,
        to: &str,
        name: &str,
        otp: &str,
        expiry_minutes: i32,
        ip_address: &str,
        user_agent: &str,
        geo_ip_service: Option<&crate::services::geoip::GeoIPService>,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("app_name", "Auth API");
        context.insert("otp_code", otp);
        context.insert("expiry_minutes", &expiry_minutes);
        context.insert(
            "login_time",
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        );
        context.insert("ip_address", ip_address);

        // Get location using geo-IP service if available
        let location = if let Some(geo_ip) = geo_ip_service {
            geo_ip.get_location_string(ip_address).await
        } else {
            "Unknown".to_string()
        };
        context.insert("location", &location);
        context.insert("user_agent", user_agent);
        context.insert("browser_info", user_agent);
        context.insert("support_url", "#");
        context.insert("security_help_url", "#");
        context.insert("help_url", "#");

        let html_body = self
            .templates
            .render("two_factor_otp", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nYour test verification code is: {}\n\nThis code will expire in {} minutes.\n\nRequest from IP: {}\nUser Agent: {}\n\nBest regards,\nThe Security Team",
            name, otp, expiry_minutes, ip_address, user_agent
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Test Verification Code".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    pub async fn send_password_reset_email_with_link(
        &self,
        to: &str,
        name: &str,
        reset_url: &str,
        expiry_minutes: i32,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("reset_link", reset_url);
        context.insert("expiry_hours", &(expiry_minutes / 60));
        context.insert("app_name", "Auth API");

        // Add missing template variables
        context.insert("support_url", "#");
        context.insert("help_url", "#");

        let html_body = self
            .templates
            .render("password_reset_email", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nYou requested a password reset for your account.\n\nClick the following link to reset your password:\n{}\n\nThis link will expire in {} minutes.\n\nIf you didn't request this reset, please ignore this email.\n\nBest regards,\nThe Security Team",
            name, reset_url, expiry_minutes
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Password Reset Request".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    pub async fn send_welcome_email(
        &self,
        to: &str,
        name: &str,
        email: &str,
        username: &str,
        account_status: &str,
        created_at: &str,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("app_name", "Auth API");
        context.insert("email", email);
        context.insert("username", username);
        context.insert("account_status", account_status);
        context.insert("created_at", created_at);

        // Add missing template variables
        context.insert("login_url", "#");
        context.insert("website_url", "#");
        context.insert("support_url", "#");
        context.insert("help_url", "#");

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

    pub async fn send_account_locked_email_with_details(
        &self,
        to: &str,
        name: &str,
        reason: &str,
        ip_address: &str,
        user_agent: &str,
        geo_ip_service: Option<&crate::services::geoip::GeoIPService>,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("app_name", "Auth API");
        context.insert("alert_type", "Account Locked");
        context.insert("details", reason);
        context.insert(
            "timestamp",
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        );
        context.insert("ip_address", ip_address);

        // Get location using geo-IP service if available
        let location = if let Some(geo_ip) = geo_ip_service {
            geo_ip.get_location_string(ip_address).await
        } else {
            "Unknown".to_string()
        };
        context.insert("location", &location);
        context.insert("user_agent", user_agent);

        // Add missing template variables
        context.insert("change_password_url", "#");
        context.insert("account_activity_url", "#");
        context.insert("security_support_url", "#");
        context.insert("security_support_email", "security@support.com");
        context.insert("privacy_url", "#");
        context.insert("terms_url", "#");
        context.insert("help_url", "#");

        let html_body = self
            .templates
            .render("security_alert_email", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nYour account has been locked by an administrator.\n\nReason: {}\n\nTime: {}\n\nIP Address: {}\nUser Agent: {}\n\nIf you believe this was done in error, please contact support.\n\nBest regards,\nThe Security Team",
            name, reason, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"), ip_address, user_agent
        );

        let request = EmailRequest {
            to: to.to_string(),
            subject: "Account Locked - Security Alert".to_string(),
            body: plain_body,
            html_body: Some(html_body),
        };

        self.send_email(request).await
    }

    pub async fn send_two_factor_email_with_details(
        &self,
        to: &str,
        name: &str,
        code: &str,
        ip_address: &str,
        user_agent: &str,
        geo_ip_service: Option<&crate::services::geoip::GeoIPService>,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("app_name", "Auth API");
        context.insert("otp_code", code);
        context.insert("expiry_minutes", &10); // 2FA codes typically expire in 10 minutes
        context.insert(
            "login_time",
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        );
        context.insert("ip_address", ip_address);

        // Get location using geo-IP service if available
        let location = if let Some(geo_ip) = geo_ip_service {
            geo_ip.get_location_string(ip_address).await
        } else {
            "Unknown".to_string()
        };
        context.insert("location", &location);
        context.insert("user_agent", user_agent);
        context.insert("browser_info", user_agent); // Use user agent as browser info
        context.insert("support_url", "#");
        context.insert("security_help_url", "#");
        context.insert("help_url", "#");

        let html_body = self
            .templates
            .render("two_factor_otp", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nYour two-factor authentication code is: {}\n\nThis code will expire in 10 minutes.\n\nLogin attempt from IP: {}\nUser Agent: {}\n\nBest regards,\nThe Security Team",
            name, code, ip_address, user_agent
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
        context.insert("app_name", "Auth API");
        context.insert("alert_type", alert_type);
        context.insert("details", details);
        context.insert(
            "timestamp",
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        );
        context.insert("ip_address", "0.0.0.0");
        context.insert("location", "Unknown");
        context.insert("user_agent", "Unknown");

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

    pub async fn send_security_alert_email_with_details(
        &self,
        to: &str,
        name: &str,
        alert_type: &str,
        details: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> AuthResult<()> {
        let mut context = Context::new();
        context.insert("name", name);
        context.insert("app_name", "Auth API");
        context.insert("alert_type", alert_type);
        context.insert("details", details);
        context.insert(
            "timestamp",
            &chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        );
        context.insert("ip_address", ip_address);
        context.insert("location", "Unknown"); // Could be enhanced with geo-IP lookup
        context.insert("user_agent", user_agent);

        let html_body = self
            .templates
            .render("security_alert_email", &context)
            .map_err(|e| AuthError::InternalError(format!("Template render error: {}", e)))?;

        let plain_body = format!(
            "Hello {},\n\nA security alert has been triggered: {}\n\nDetails: {}\n\nTime: {}\n\nIP Address: {}\nUser Agent: {}\n\nIf this wasn't you, please change your password immediately.\n\nBest regards,\nThe Security Team",
            name, alert_type, details, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"), ip_address, user_agent
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
        context.insert("verification_link", verification_url);
        context.insert("expiry_hours", &24); // 24 hours expiry
        context.insert("app_name", "Auth API");

        let html_body = self
            .templates
            .render("email_verification", &context)
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
