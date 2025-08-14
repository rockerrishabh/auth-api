use lettre::{
    message::{header::ContentType, Mailbox},
    Message,
};
use std::env;

pub fn password_reset_email(name: &str, email: &str, reset_token: &str) -> Message {
    let from_email = env::var("SMTP_USER").unwrap_or_else(|_| "noreply@example.com".to_string());
    let from_name = env::var("SMTP_USER_NAME").unwrap_or_else(|_| "Auth API".to_string());
    let base_url = env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    
    let from: Mailbox = format!("{} <{}>", from_name, from_email)
        .parse()
        .expect("Invalid from email");
    
    let to: Mailbox = format!("{} <{}>", name, email)
        .parse()
        .expect("Invalid to email");

    let reset_url = format!("{}/reset-password?token={}", base_url, reset_token);

    let html_body = format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            border-radius: 8px 8px 0 0;
        }}
        .content {{
            background-color: #ffffff;
            padding: 30px;
            border: 1px solid #e9ecef;
        }}
        .footer {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            border-radius: 0 0 8px 8px;
            font-size: 14px;
            color: #6c757d;
        }}
        .button {{
            display: inline-block;
            padding: 12px 24px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .button:hover {{
            background-color: #0056b3;
        }}
        .warning {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .code {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Password Reset Request</h1>
    </div>
    
    <div class="content">
        <p>Hello {name},</p>
        
        <p>We received a request to reset your password for your account. If you made this request, click the button below to reset your password:</p>
        
        <div style="text-align: center;">
            <a href="{reset_url}" class="button">Reset Password</a>
        </div>
        
        <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
        <div class="code">{reset_url}</div>
        
        <div class="warning">
            <strong>Important:</strong>
            <ul>
                <li>This link will expire in 1 hour for security reasons</li>
                <li>If you didn't request this password reset, please ignore this email</li>
                <li>Your password will remain unchanged until you create a new one</li>
            </ul>
        </div>
        
        <p>If you're having trouble with the password reset process, please contact our support team.</p>
        
        <p>Best regards,<br>The Auth API Team</p>
    </div>
    
    <div class="footer">
        <p>This is an automated message, please do not reply to this email.</p>
        <p>If you have any questions, please contact our support team.</p>
    </div>
</body>
</html>
        "#,
        name = name,
        reset_url = reset_url
    );

    let text_body = format!(
        r#"
Password Reset Request

Hello {name},

We received a request to reset your password for your account. If you made this request, please visit the following link to reset your password:

{reset_url}

Important:
- This link will expire in 1 hour for security reasons
- If you didn't request this password reset, please ignore this email
- Your password will remain unchanged until you create a new one

If you're having trouble with the password reset process, please contact our support team.

Best regards,
The Auth API Team

---
This is an automated message, please do not reply to this email.
If you have any questions, please contact our support team.
        "#,
        name = name,
        reset_url = reset_url
    );

    Message::builder()
        .from(from)
        .to(to)
        .subject("Password Reset Request")
        .header(ContentType::TEXT_HTML)
        .multipart(
            lettre::message::MultiPart::alternative()
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )
        .expect("Failed to build password reset email")
}