use crate::db::model::User;

pub fn create_password_change_confirmation_html(user: &User) -> String {
    format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Changed Successfully</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8fafc;
                }}
                .container {{
                    background-color: #ffffff;
                    border-radius: 12px;
                    padding: 40px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .logo {{
                    width: 60px;
                    height: 60px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    border-radius: 12px;
                    margin: 0 auto 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .logo svg {{
                    width: 30px;
                    height: 30px;
                    color: white;
                }}
                .title {{
                    color: #1e293b;
                    font-size: 24px;
                    font-weight: 700;
                    margin-bottom: 10px;
                }}
                .subtitle {{
                    color: #64748b;
                    font-size: 16px;
                }}
                .content {{
                    margin: 30px 0;
                    padding: 20px;
                    background-color: #f1f5f9;
                    border-radius: 8px;
                    border-left: 4px solid #10b981;
                }}
                .info-item {{
                    margin: 15px 0;
                    display: flex;
                    align-items: center;
                }}
                .info-label {{
                    font-weight: 600;
                    color: #374151;
                    min-width: 120px;
                }}
                .info-value {{
                    color: #6b7280;
                    margin-left: 10px;
                }}
                .security-note {{
                    background-color: #fef3c7;
                    border: 1px solid #f59e0b;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 30px 0;
                }}
                .security-title {{
                    color: #92400e;
                    font-weight: 600;
                    margin-bottom: 10px;
                    display: flex;
                    align-items: center;
                }}
                .security-icon {{
                    width: 20px;
                    height: 20px;
                    margin-right: 8px;
                }}
                .security-text {{
                    color: #78350f;
                    font-size: 14px;
                    line-height: 1.5;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #e2e8f0;
                    color: #64748b;
                    font-size: 14px;
                }}
                .button {{
                    display: inline-block;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    padding: 12px 24px;
                    border-radius: 8px;
                    font-weight: 600;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">
                        <svg fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <h1 class="title">Password Changed Successfully</h1>
                    <p class="subtitle">Your account security has been updated</p>
                </div>

                <div class="content">
                    <p>Hello <strong>{name}</strong>,</p>
                    <p>Your password has been successfully changed. Here are the details of this action:</p>
                    
                    <div class="info-item">
                        <span class="info-label">Account:</span>
                        <span class="info-value">{email}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Action:</span>
                        <span class="info-value">Password Change</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Time:</span>
                        <span class="info-value">{timestamp}</span>
                    </div>
                </div>

                <div class="security-note">
                    <div class="security-title">
                        <svg class="security-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                        </svg>
                        Security Notice
                    </div>
                    <div class="security-text">
                        <p><strong>If you did not change your password:</strong></p>
                        <ul>
                            <li>Immediately change your password again</li>
                            <li>Check your account for any suspicious activity</li>
                            <li>Contact our support team if you have concerns</li>
                        </ul>
                    </div>
                </div>

                <div style="text-align: center;">
                    <a href="{login_url}" class="button">Go to Login</a>
                </div>

                <div class="footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                    <p>If you have any questions, contact our support team.</p>
                </div>
            </div>
        </body>
        </html>
        "#,
        name = user.name,
        email = user.email,
        timestamp = chrono::Utc::now().format("%B %d, %Y at %I:%M %p UTC").to_string(),
        login_url = std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()) + "/login"
    )
}

pub fn create_password_change_confirmation_text(user: &User) -> String {
    format!(
        r#"
Password Changed Successfully

Hello {},

Your password has been successfully changed. Here are the details of this action:

Account: {}
Action: Password Change
Time: {}

SECURITY NOTICE:
If you did not change your password:
- Immediately change your password again
- Check your account for any suspicious activity
- Contact our support team if you have concerns

Go to Login: {}/login

This is an automated message. Please do not reply to this email.
If you have any questions, contact our support team.
        "#,
        user.name,
        user.email,
        chrono::Utc::now().format("%B %d, %Y at %I:%M %p UTC").to_string(),
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    )
}
