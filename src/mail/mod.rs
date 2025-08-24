pub mod templates;

use lettre::{
    message::{header::ContentType, Mailbox, MultiPart, SinglePart},
    transport::smtp::{authentication::Credentials, response::Response, Error as SmtpError},
    Message, SmtpTransport, Transport,
};

use crate::{
    config::EmailConfig,
    db::model::User,
    mail::templates::{
        email_change_verification::{
            create_email_change_verification_html, create_email_change_verification_text,
        },
        password_change_confirmation::{
            create_password_change_confirmation_html, create_password_change_confirmation_text,
        },
        password_reset::{create_password_reset_html, create_password_reset_text},
        verification::{create_verification_html, create_verification_text},
        verification_confirmation::{
            create_verification_confirmation_html, create_verification_confirmation_text,
        },
    },
};

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("SMTP error: {0}")]
    Smtp(#[from] SmtpError),
    #[error("Message building error: {0}")]
    MessageBuild(#[from] lettre::error::Error),
    #[error("Email parsing error: {0}")]
    EmailParse(#[from] lettre::address::AddressError),
}

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to_name: String,
    pub to_email: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: Option<String>,
}

#[derive(Clone)]
pub struct EmailService {
    config: EmailConfig,
    transport: SmtpTransport,
}

impl EmailService {
    pub fn new(config: EmailConfig) -> Result<Self, EmailError> {
        let creds = Credentials::new(config.from_email.clone(), config.smtp_password.clone());

        let transport = SmtpTransport::starttls_relay(&config.smtp_server)?
            .port(config.smtp_port)
            .credentials(creds)
            .build();

        Ok(EmailService { config, transport })
    }

    pub fn send_message(&self, email_message: EmailMessage) -> Result<Response, EmailError> {
        let from: Mailbox =
            format!("{} <{}>", self.config.from_name, self.config.from_email).parse()?;

        let to: Mailbox =
            format!("{} <{}>", email_message.to_name, email_message.to_email).parse()?;

        let message_builder = Message::builder()
            .from(from.clone())
            .reply_to(from)
            .to(to)
            .subject(email_message.subject);

        // Create multipart message if both HTML and text are provided
        let message = if let Some(text_body) = email_message.text_body {
            message_builder.multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(email_message.html_body),
                    ),
            )?
        } else {
            message_builder
                .header(ContentType::TEXT_HTML)
                .body(email_message.html_body)?
        };

        self.transport.send(&message).map_err(EmailError::from)
    }

    pub fn send_verification_email(
        &self,
        name: &str,
        email: &str,
        verification_token: &str,
        frontend_url: &str,
    ) -> Result<Response, EmailError> {
        let verification_url = format!("{}/verify?token={}", frontend_url, verification_token);

        let html_body = create_verification_html(name, &verification_url);
        let text_body = create_verification_text(name, &verification_url);

        let email_message = EmailMessage {
            to_name: name.to_string(),
            to_email: email.to_string(),
            subject: "Please verify your email address".to_string(),
            html_body,
            text_body: Some(text_body),
        };

        self.send_message(email_message)
    }

    pub fn send_password_reset_email(
        &self,
        name: &str,
        email: &str,
        reset_token: &str,
        frontend_url: &str,
    ) -> Result<Response, EmailError> {
        let reset_url = format!("{}/reset-password?token={}", frontend_url, reset_token);

        let html_body = create_password_reset_html(name, &reset_url);
        let text_body = create_password_reset_text(name, &reset_url);

        let email_message = EmailMessage {
            to_name: name.to_string(),
            to_email: email.to_string(),
            subject: "Password Reset Request".to_string(),
            html_body,
            text_body: Some(text_body),
        };

        self.send_message(email_message)
    }

    pub fn send_password_change_confirmation_email(
        &self,
        user: &User,
    ) -> Result<Response, EmailError> {
        let html_body = create_password_change_confirmation_html(user);
        let text_body = create_password_change_confirmation_text(user);

        let email_message = EmailMessage {
            to_name: user.name.clone(),
            to_email: user.email.clone(),
            subject: "Password Changed Successfully".to_string(),
            html_body,
            text_body: Some(text_body),
        };

        self.send_message(email_message)
    }

    pub fn send_verification_confirmation_email(
        &self,
        user: &User,
    ) -> Result<Response, EmailError> {
        let html_body = create_verification_confirmation_html(user);
        let text_body = create_verification_confirmation_text(user);

        let email_message = EmailMessage {
            to_name: user.name.clone(),
            to_email: user.email.clone(),
            subject: "Email Verified Successfully!".to_string(),
            html_body,
            text_body: Some(text_body),
        };

        self.send_message(email_message)
    }

    pub fn send_email_change_verification_email(
        &self,
        name: &str,
        new_email: &str,
        verification_token: &str,
        frontend_url: &str,
    ) -> Result<Response, EmailError> {
        let verification_url = format!("{}/verify?token={}", frontend_url, verification_token);

        let html_body = create_email_change_verification_html(name, new_email, &verification_url);
        let text_body = create_email_change_verification_text(name, new_email, &verification_url);

        let email_message = EmailMessage {
            to_name: name.to_string(),
            to_email: new_email.to_string(),
            subject: "Verify Your New Email Address".to_string(),
            html_body,
            text_body: Some(text_body),
        };

        self.send_message(email_message)
    }
}
