pub fn create_password_reset_html(name: &str, reset_url: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Request</title>
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
            background-color: #dc3545;
            padding: 20px;
            text-align: center;
            border-radius: 8px 8px 0 0;
            color: white;
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
            background-color: #dc3545;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .button:hover {{
            background-color: #c82333;
        }}
        .info {{
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
        .warning {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Password Reset Request</h1>
    </div>
    
    <div class="content">
        <p>Hello {name},</p>
        
        <p>We received a request to reset your password. If you made this request, please click the button below to reset your password:</p>
        
        <div style="text-align: center;">
            <a href="{reset_url}" class="button">Reset Password</a>
        </div>
        
        <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
        <div class="code">{reset_url}</div>
        
        <div class="warning">
            <strong>Security Notice:</strong>
            <ul>
                <li>This password reset link will expire in 1 hour</li>
                <li>If you didn't request a password reset, please ignore this email</li>
                <li>Your current password will remain unchanged</li>
                <li>For security, this link can only be used once</li>
            </ul>
        </div>
        
        <div class="info">
            <strong>Tips for a strong password:</strong>
            <ul>
                <li>Use at least 8 characters</li>
                <li>Include uppercase and lowercase letters</li>
                <li>Include numbers and special characters</li>
                <li>Don't use personal information</li>
                <li>Don't reuse passwords from other accounts</li>
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
    )
}

pub fn create_password_reset_text(name: &str, reset_url: &str) -> String {
    format!(
        r#"
Password Reset Request

Hello {name},

We received a request to reset your password. If you made this request, please visit the following link to reset your password:

{reset_url}

Security Notice:
- This password reset link will expire in 1 hour
- If you didn't request a password reset, please ignore this email
- Your current password will remain unchanged
- For security, this link can only be used once

Tips for a strong password:
- Use at least 8 characters
- Include uppercase and lowercase letters
- Include numbers and special characters
- Don't use personal information
- Don't reuse passwords from other accounts

If you're having trouble with the password reset process, please contact our support team.

Best regards,
The Auth API Team

---
This is an automated message, please do not reply to this email.
If you have any questions, please contact our support team.
        "#,
        name = name,
        reset_url = reset_url
    )
}
