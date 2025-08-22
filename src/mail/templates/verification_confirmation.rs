use crate::db::model::User;

pub fn create_verification_confirmation_html(user: &User) -> String {
    format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Verified Successfully</title>
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
                    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
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
                    background-color: #f0fdf4;
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
                .benefits {{
                    background-color: #ecfdf5;
                    border: 1px solid #10b981;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 30px 0;
                }}
                .benefits-title {{
                    color: #065f46;
                    font-weight: 600;
                    margin-bottom: 15px;
                    display: flex;
                    align-items: center;
                }}
                .benefits-icon {{
                    width: 20px;
                    height: 20px;
                    margin-right: 8px;
                }}
                .benefits-list {{
                    color: #047857;
                    font-size: 14px;
                    line-height: 1.6;
                }}
                .benefits-list ul {{
                    margin: 10px 0;
                    padding-left: 20px;
                }}
                .benefits-list li {{
                    margin: 5px 0;
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
                    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
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
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <h1 class="title">Email Verified Successfully!</h1>
                    <p class="subtitle">Welcome to the full AuthApp experience</p>
                </div>

                <div class="content">
                    <p>Hello <strong>{name}</strong>,</p>
                    <p>Congratulations! Your email address has been successfully verified. Here are the details:</p>
                    
                    <div class="info-item">
                        <span class="info-label">Account:</span>
                        <span class="info-value">{email}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Status:</span>
                        <span class="info-value">✅ Verified</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Verified at:</span>
                        <span class="info-value">{timestamp}</span>
                    </div>
                </div>

                <div class="benefits">
                    <div class="benefits-title">
                        <svg class="benefits-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M6.267 3.455a3.066 3.066 0 001.745-.723 3.066 3.066 0 013.976 0 3.066 3.066 0 001.745.723 3.066 3.066 0 012.812 2.812c.051.643.304 1.254.723 1.745a3.066 3.066 0 010 3.976 3.066 3.066 0 00-.723 1.745 3.066 3.066 0 01-2.812 2.812 3.066 3.066 0 00-1.745.723 3.066 3.066 0 01-3.976 0 3.066 3.066 0 00-1.745-.723 3.066 3.066 0 01-2.812-2.812 3.066 3.066 0 00-.723-1.745 3.066 3.066 0 010-3.976 3.066 3.066 0 00.723-1.745 3.066 3.066 0 012.812-2.812zm7.44 5.252a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                        </svg>
                        What You Can Do Now
                    </div>
                    <div class="benefits-list">
                        <ul>
                            <li>Access all features of your account</li>
                            <li>Receive important notifications</li>
                            <li>Reset your password if needed</li>
                            <li>Update your profile information</li>
                            <li>Enjoy enhanced security features</li>
                        </ul>
                    </div>
                </div>

                <div style="text-align: center;">
                    <a href="{dashboard_url}" class="button">Go to Dashboard</a>
                </div>

                <div class="footer">
                    <p>Thank you for verifying your email address!</p>
                    <p>If you have any questions, contact our support team.</p>
                </div>
            </div>
        </body>
        </html>
        "#,
        name = user.name,
        email = user.email,
        timestamp = chrono::Utc::now().format("%B %d, %Y at %I:%M %p UTC").to_string(),
        dashboard_url = std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()) + "/dashboard"
    )
}

pub fn create_verification_confirmation_text(user: &User) -> String {
    format!(
        r#"
Email Verified Successfully!

Hello {},

Congratulations! Your email address has been successfully verified.

Account: {}
Status: ✅ Verified
Verified at: {}

What You Can Do Now:
- Access all features of your account
- Receive important notifications
- Reset your password if needed
- Update your profile information
- Enjoy enhanced security features

Go to Dashboard: {}/dashboard

Thank you for verifying your email address!
If you have any questions, contact our support team.
        "#,
        user.name,
        user.email,
        chrono::Utc::now().format("%B %d, %Y at %I:%M %p UTC").to_string(),
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    )
}
