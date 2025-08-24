pub fn create_email_change_verification_html(name: &str, new_email: &str, verification_url: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Change Verification</title>
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
        .warning {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Verify Your New Email Address</h1>
    </div>
    
    <div class="content">
        <p>Hello {name},</p>
        
        <p>You have requested to change your email address to <strong>{new_email}</strong>.</p>
        
        <p>To complete this change and verify your new email address, please click the button below:</p>
        
        <div style="text-align: center;">
            <a href="{verification_url}" class="button">Verify New Email Address</a>
        </div>
        
        <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
        <div class="code">{verification_url}</div>
        
        <div class="warning">
            <strong>Important:</strong>
            <ul>
                <li>This verification link will expire in 24 hours</li>
                <li>If you didn't request this email change, please ignore this email and contact support immediately</li>
                <li>Your account will remain secure with your current email until verification is complete</li>
            </ul>
        </div>
        
        <div class="info">
            <strong>What happens next:</strong>
            <ul>
                <li>Once verified, your new email address will be active for your account</li>
                <li>You'll receive a confirmation email at your new address</li>
                <li>Future communications will be sent to your new email address</li>
            </ul>
        </div>
        
        <p>If you're having trouble with the verification process, please contact our support team.</p>
        
        <p>Best regards,<br>The Auth API Team</p>
    </div>
    
    <div class="footer">
        <p>This is an automated message, please do not reply to this email.</p>
        <p>If you have any questions, please contact our support team.</p>
    </div>
</body>
</html>
"#
    )
}

pub fn create_email_change_verification_text(name: &str, new_email: &str, verification_url: &str) -> String {
    format!(
        r#"
Verify Your New Email Address

Hello {name},

You have requested to change your email address to {new_email}.

To complete this change and verify your new email address, please visit the following link:

{verification_url}

IMPORTANT:
- This verification link will expire in 24 hours
- If you didn't request this email change, please ignore this email and contact support immediately
- Your account will remain secure with your current email until verification is complete

What happens next:
- Once verified, your new email address will be active for your account
- You'll receive a confirmation email at your new address
- Future communications will be sent to your new email address

If you're having trouble with the verification process, please contact our support team.

Best regards,
The Auth API Team

---
This is an automated message, please do not reply to this email.
If you have any questions, please contact our support team.
"#
    )
}
