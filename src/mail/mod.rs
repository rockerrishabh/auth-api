pub mod templates;

use lettre::{
    Message, SmtpTransport, Transport,
    message::{Mailbox, header::ContentType},
    transport::smtp::{Error, authentication::Credentials, response::Response},
};

pub struct EmailInfo {
    user_name: String,
    user_email: String,
    subject: String,
    html: String,
}

pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_user_name: String,
    pub smtp_password: String,
}

pub fn send_email(info: EmailInfo, config: &EmailConfig) -> Result<Response, Error> {
    let email = Message::builder()
        .from(Mailbox::new(
            Some(config.smtp_user_name.to_owned()),
            config.smtp_user.parse().unwrap(),
        ))
        .reply_to(Mailbox::new(
            Some(config.smtp_user_name.to_owned()),
            config.smtp_user.parse().unwrap(),
        ))
        .to(Mailbox::new(
            Some(info.user_name.to_owned()),
            info.user_email.parse().unwrap(),
        ))
        .subject(info.subject)
        .header(ContentType::TEXT_HTML)
        .body(info.html)
        .unwrap();

    let creds = Credentials::new(config.smtp_user.to_owned(), config.smtp_password.to_owned());

    // Open a remote connection to gmail
    let mailer = SmtpTransport::relay(config.smtp_server.as_str())
        .unwrap()
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    // Send the email
    mailer.send(&email)
}
