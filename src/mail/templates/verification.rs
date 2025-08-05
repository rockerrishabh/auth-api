use uuid::Uuid;

use crate::mail::EmailInfo;

pub fn verification_email(name: &String, email: &String, token: Uuid) -> EmailInfo {
    let subject = "Please verify your email address".to_string();
    let html = format!(
        r#"
        <p>Hi {name},</p>
        <p>Thank you for registering. Please click the link below to verify your email address:</p>
        <p><a href='https://stellerseller.store/verify?token={token}'>{email}</a></p>
        <p>If you did not register, please ignore this email.</p>
    "#
    );

    EmailInfo {
        user_name: name.clone(),
        user_email: email.clone(),
        subject,
        html,
    }
}
