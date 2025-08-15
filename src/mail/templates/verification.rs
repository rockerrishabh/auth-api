pub fn create_verification_html(name: &str, verification_url: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification</title>
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
            background-color: #28a745;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .button:hover {{
            background-color: #218838;
        }}
        .info {{
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
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
        <h1>Welcome! Please Verify Your Email</h1>
    </div>
    
    <div class="content">
        <p>Hello {name},</p>
        
        <p>Thank you for registering with us! To complete your account setup, please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center;">
            <a href="{verification_url}" class="button">Verify Email Address</a>
        </div>
        
        <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
        <div class="code">{verification_url}</div>
        
        <div class="info">
            <strong>Note:</strong>
            <ul>
                <li>This verification link will expire in 24 hours</li>
                <li>If you didn't create an account, please ignore this email</li>
                <li>You won't be able to log in until your email is verified</li>
            </ul>
        </div>
        
        <p>If you're having trouble with the verification process, please contact our support team.</p>
        
        <p>Welcome aboard!<br>The Auth API Team</p>
    </div>
    
    <div class="footer">
        <p>This is an automated message, please do not reply to this email.</p>
        <p>If you have any questions, please contact our support team.</p>
    </div>
</body>
</html>
        "#,
        name = name,
        verification_url = verification_url
    )
}

pub fn create_verification_text(name: &str, verification_url: &str) -> String {
    format!(
        r#"
Welcome! Please Verify Your Email

Hello {name},

Thank you for registering with us! To complete your account setup, please verify your email address by visiting the following link:

{verification_url}

Note:
- This verification link will expire in 24 hours
- If you didn't create an account, please ignore this email
- You won't be able to log in until your email is verified

If you're having trouble with the verification process, please contact our support team.

Welcome aboard!
The Auth API Team

---
This is an automated message, please do not reply to this email.
If you have any questions, please contact our support team.
        "#,
        name = name,
        verification_url = verification_url
    )
}
