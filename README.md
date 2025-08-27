# 🔐 Auth API - Enterprise Authentication System

A comprehensive, production-ready authentication API built with Rust, Actix Web, and PostgreSQL. This system provides enterprise-grade security with modern authentication features, user management, administrative controls, and advanced security monitoring including geo-IP location tracking.

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![PostgreSQL](https://img.shields.io/badge/postgresql-12+-blue.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Geo-IP](https://img.shields.io/badge/geo--ip-enabled-success.svg)](https://www.maxmind.com/)

## 🚀 Features

### Core Authentication

- ✅ **User Registration** with email verification
- ✅ **Secure Login** with JWT access/refresh tokens
- ✅ **Token Rotation** for enhanced security
- ✅ **Password Reset** with JWT URL verification
- ✅ **Email Verification** system
- ✅ **Two-Factor Authentication** (2FA) support
- ✅ **Secure Logout** with token revocation

### Authorization & Access Control

- ✅ **Role-Based Access Control** (RBAC)
- ✅ **Admin Dashboard** and user management
- ✅ **Route-Level Authentication** middleware
- ✅ **Protected and Public Route** separation
- ✅ **Session Management** and tracking

### Security Features

- ✅ **Argon2 Password Hashing** (PHC winner)
- ✅ **JWT Token Signing** and verification
- ✅ **Rate Limiting** middleware
- ✅ **CORS Configuration**
- ✅ **Input Validation** and sanitization
- ✅ **Secure File Upload** handling
- ✅ **Alphanumeric OTP Generation** and verification
- ✅ **Account Lockout** protection
- ✅ **Geo-IP Location Tracking** with caching
- ✅ **Real User Data in Security Emails** (no placeholders)
- ✅ **Advanced Security Monitoring** and alerting

### File Management

- ✅ **Avatar Upload** with image processing
- ✅ **Thumbnail Generation** (WebP format)
- ✅ **File Size Tracking** and analytics
- ✅ **File Type Validation**
- ✅ **Static File Serving**

### Advanced Security Features

- ✅ **Geo-IP Location Detection** - Track user locations in security events
- ✅ **Security Email Templates** - Professional alerts with real user data
- ✅ **Cache Management** - Admin endpoints for cache statistics and clearing
- ✅ **Activity Auditing** - Comprehensive user activity tracking
- ✅ **System Health Monitoring** - Built-in health checks and diagnostics
- ✅ **Dynamic Configuration** - Runtime system settings management

### Developer Experience

- ✅ **Comprehensive Error Handling**
- ✅ **Clean Architecture** with services
- ✅ **Configuration Management** (Environment variables)
- ✅ **Database Migrations** with Diesel
- ✅ **Advanced Email Templating** with real data integration
- ✅ **Logging and Monitoring** ready
- ✅ **Production-Ready** with Docker support

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Geo-IP Configuration](#geo-ip-configuration)
- [API Documentation](#api-documentation)
- [Database Schema](#database-schema)
- [Email Templates](#email-templates)
- [Development](#development)
- [Security Features](#security-features)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

## 📋 Prerequisites

- **Rust** 1.70 or higher
- **PostgreSQL** 12 or higher
- **SMTP Server** access (for email functionality)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd auth-api

# Install dependencies
cargo build
```

### 2. Database Setup

```bash
# Create PostgreSQL database
createdb auth_db

# Run migrations
diesel migration run
```

### 3. Configuration

```bash
# Copy environment template
cp env.example .env

# Edit with your values
nano .env
```

### 4. Run the Application

```bash
cargo run
```

The API will be available at `http://localhost:5000`

## ⚙️ Configuration

### Environment Variables

The application uses the following environment variables (with `APP_` prefix):

#### Application Settings

```bash
ENVIRONMENT=development
APP_HOST=0.0.0.0
APP_PORT=5000
APP_FRONTEND__URL=http://localhost:3000
```

#### Database Configuration

```bash
APP_DATABASE__URL=postgresql://username:password@localhost:5432/auth_db
APP_DATABASE__MAX_CONNECTIONS=10
APP_DATABASE__MIN_CONNECTIONS=2
APP_DATABASE__CONNECT_TIMEOUT=10
APP_DATABASE__IDLE_TIMEOUT=300
APP_DATABASE__MAX_LIFETIME=3600
```

#### JWT Configuration

```bash
APP_JWT__SECRET=your-super-secret-jwt-key-here-make-it-long-and-random-at-least-32-characters
APP_JWT__ACCESS_TOKEN_EXPIRY=3600
APP_JWT__REFRESH_TOKEN_EXPIRY=86400
```

#### Email Configuration

```bash
APP_EMAIL__SMTP_HOST=smtp.gmail.com
APP_EMAIL__SMTP_PORT=587
APP_EMAIL__SMTP_USERNAME=your-email@gmail.com
APP_EMAIL__SMTP_PASSWORD=your-app-password
APP_EMAIL__FROM_EMAIL=noreply@yourapp.com
APP_EMAIL__FROM_NAME=Your App Name
```

#### Security Configuration

```bash
APP_SECURITY__MAX_FAILED_ATTEMPTS=5
APP_SECURITY__SESSION_TIMEOUT=86400
APP_TWO_FACTOR__REQUIRED_ROLES=admin,super_admin
```

**Note:** `APP_TWO_FACTOR__REQUIRED_ROLES` is a comma-separated list of user roles that require 2FA. Users with these roles must enable 2FA before they can log in. This provides an additional security layer for sensitive accounts.

#### File Upload Configuration

```bash
APP_UPLOAD__DIR=./static
APP_UPLOAD__MAX_SIZE=10485760
APP_UPLOAD__IMAGE_MAX_WIDTH=1920
APP_UPLOAD__IMAGE_MAX_HEIGHT=1080
APP_UPLOAD__IMAGE_QUALITY=75
APP_UPLOAD__THUMBNAIL_SIZE=300
APP_UPLOAD__GENERATE_THUMBNAILS=true
APP_UPLOAD__ALLOWED_TYPES=["jpg","jpeg","png","gif","webp"]
```

#### Geo-IP Configuration

```bash
APP_GEO_IP__ENABLED=false
APP_GEO_IP__CACHE_ENABLED=true
APP_GEO_IP__API_ENDPOINT=http://ip-api.com/json
APP_GEO_IP__TIMEOUT_SECONDS=5
```

### Configuration Files

The application supports layered configuration:

1. **Default Config** (`config/default.toml`) - Base configuration
2. **Environment Config** (`config/{environment}.toml`) - Environment-specific overrides
3. **Local Config** (`config/local.toml`) - Personal development settings
4. **Environment Variables** - Highest priority overrides

## 🌍 Geo-IP Configuration

The application includes advanced geo-IP location tracking that provides real geographic information in security emails instead of generic "Unknown" placeholders.

### Geo-IP Features

- **📍 Real Location Detection** - Converts IP addresses to city/country information
- **⚡ Intelligent Caching** - Reduces API calls and improves performance
- **🛡️ Privacy-Aware** - Handles local/private IPs appropriately
- **🔄 Graceful Degradation** - Falls back to "Unknown" if geo-IP fails
- **⚙️ Admin Management** - Cache statistics and clearing endpoints

### Configuration Options

| Variable                      | Default                  | Description                             |
| ----------------------------- | ------------------------ | --------------------------------------- |
| `APP_GEO_IP__ENABLED`         | `false`                  | Enable/disable geo-IP location tracking |
| `APP_GEO_IP__CACHE_ENABLED`   | `true`                   | Enable caching for better performance   |
| `APP_GEO_IP__API_ENDPOINT`    | `http://ip-api.com/json` | Geo-IP API service endpoint             |
| `APP_GEO_IP__TIMEOUT_SECONDS` | `5`                      | Request timeout in seconds              |

### Example Locations

**Before Geo-IP:**

- Location: Unknown
- IP: 8.8.8.8

**After Geo-IP:**

- Location: Mountain View, United States
- IP: 8.8.8.8

**Local/Private IPs:**

- Location: Local Network, Localhost
- IP: 127.0.0.1

### Admin Endpoints

```bash
# Get cache statistics
GET /admin/system/cache/stats

# Clear geo-IP cache
POST /admin/system/cache/clear
```

## 📚 API Documentation

### Base URL

```
http://localhost:5000/v1
```

### Authentication Endpoints

#### Public Routes (No Authentication Required)

```
POST /auth/register                    - User registration
POST /auth/login                       - User login
POST /auth/password-reset              - Request password reset
GET  /auth/password-reset/verify       - Verify password reset token
GET  /auth/email-verification/verify   - Verify email with token
POST /auth/email-verification/resend   - Resend verification email
```

#### Protected Routes (Authentication Required)

```
POST /auth/logout                      - User logout
POST /auth/refresh                     - Refresh access token
GET  /auth/profile                     - Get user profile
PUT  /auth/profile                     - Update user profile
POST /auth/change-password             - Change user password
GET  /auth/preferences                 - Get user preferences
PUT  /auth/preferences                 - Update user preferences
GET  /auth/sessions                    - Get user sessions
DELETE /auth/sessions/{id}             - Revoke specific session
DELETE /auth/sessions/revoke-other     - Revoke other sessions
POST /auth/upload/avatar               - Upload user avatar
POST /auth/password-reset/complete     - Complete password reset with JWT token
```

#### Two-Factor Authentication

```
POST /auth/two-factor/setup            - Setup 2FA with QR code
POST /auth/two-factor/enable           - Enable 2FA with verification
POST /auth/two-factor/verify           - Verify 2FA code
POST /auth/two-factor/disable          - Disable 2FA
POST /auth/two-factor/send-login-otp   - Send OTP for login verification
```

#### User Management

```
PUT  /auth/user/email                  - Update email
PUT  /auth/user/phone                  - Update phone
PUT  /auth/user/name                   - Update name
PUT  /auth/user/password               - Update password (admin)
PUT  /auth/user/avatar                 - Update avatar
PUT  /auth/user/verification           - Update verification status
POST /auth/user/lock                   - Lock user account
GET  /auth/user/statistics             - Get user statistics
GET  /auth/user/search                 - Search users
```

#### Session Management

```
GET  /auth/sessions/current            - Get current session
GET  /auth/sessions/all                - Get all user sessions
DELETE /auth/sessions/{id}             - Revoke specific session
DELETE /auth/sessions/revoke-other     - Revoke other sessions
GET  /auth/sessions/count              - Get session count
```

#### Email Services

```
POST /auth/email/send                  - Send custom email
POST /auth/email/welcome               - Send welcome email
POST /auth/email/security-alert        - Send security alert
POST /auth/email/test-otp              - Test OTP email
```

#### OTP Management

```
POST /auth/otp/create                  - Create custom OTP
POST /auth/otp/verify                  - Verify OTP
GET  /auth/otp/{id}                    - Get OTP details
POST /auth/otp/cleanup                 - Cleanup expired OTPs
POST /auth/otp/demo                    - Demo OTP methods
```

#### Password Utilities

```
POST /auth/password/validate-strength  - Validate password strength
POST /auth/password/generate-secure    - Generate secure password
POST /auth/password/hash               - Hash password
POST /auth/password/hash-and-validate  - Hash and validate password
```

#### Activity Tracking

```
POST /auth/activity/log                - Log user activity
GET  /auth/activity/my                 - Get my activities
GET  /auth/activity/recent             - Get recent activities
GET  /auth/activity/summary            - Get activity summary
GET  /auth/activity/logins-today       - Get today's logins
GET  /auth/activity/logins-week        - Get weekly logins
GET  /auth/activity/logins-month       - Get monthly logins
GET  /auth/activity/failed-attempts    - Get failed login attempts
GET  /auth/activity/audit-logs         - Get audit logs
```

### Admin Endpoints (Admin Role Required)

#### User Management

```
GET  /admin/users                      - List all users
GET  /admin/users/{id}                 - Get user by ID
PUT  /admin/users/{id}/role            - Update user role
PUT  /admin/users/{id}/status          - Update user status
DELETE /admin/users/{id}               - Delete user
GET  /admin/users/search               - Search users
GET  /admin/users/statistics           - Get user statistics
POST /admin/users/bulk-update          - Bulk update users
GET  /admin/users/export               - Export users (CSV)
```

#### Dashboard & Analytics

```
GET  /admin/dashboard/stats            - Get dashboard statistics
GET  /admin/dashboard/activity         - Get activity statistics
GET  /admin/dashboard/roles            - Get role distribution
GET  /admin/dashboard/health           - Get system health
GET  /admin/dashboard/info             - Get system info
GET  /admin/dashboard/user-stats       - Get user statistics
GET  /admin/dashboard/timeline         - Get activity timeline
```

#### Audit & Security

```
GET  /admin/audit/logs                - Get audit logs
GET  /admin/audit/summary             - Get audit summary
GET  /admin/audit/user/{id}           - Get user audit logs
```

#### System Management

```
GET  /admin/system/config             - Get system configuration
PUT  /admin/system/config             - Update system configuration
POST /admin/system/initialize         - Initialize system settings
GET  /admin/system/settings           - Get all system settings
GET  /admin/system/health             - Get system health
GET  /admin/system/cache/stats        - Get geo-IP cache statistics
POST /admin/system/cache/clear        - Clear geo-IP cache
```

### Utility Endpoints

```
GET  /health                          - Health check
GET  /health/detailed                 - Detailed health check
GET  /static/{filename}               - Serve static files
```

## 🗄️ Database Schema

### Core Tables

#### users

```sql
- id (UUID, Primary Key)
- username (VARCHAR, Unique)
- email (VARCHAR, Unique)
- password_hash (VARCHAR)
- name (VARCHAR)
- role (user_role ENUM)
- email_verified (BOOLEAN)
- email_verified_at (TIMESTAMPTZ)
- phone (VARCHAR)
- phone_verified (BOOLEAN)
- two_factor_enabled (BOOLEAN)
- two_factor_secret (VARCHAR)
- last_login_at (TIMESTAMPTZ)
- last_login_ip (VARCHAR)
- failed_login_attempts (INTEGER)
- locked_until (TIMESTAMPTZ)
- account_status (account_status ENUM)
- avatar (VARCHAR)
- avatar_thumbnail (VARCHAR)
- preferences (JSONB)
- created_at (TIMESTAMPTZ)
- updated_at (TIMESTAMPTZ)
- deleted_at (TIMESTAMPTZ)
```

#### otps

```sql
- id (UUID, Primary Key)
- user_id (UUID, Foreign Key)
- otp_type (otp_type ENUM)
- code (VARCHAR)
- expires_at (TIMESTAMPTZ)
- attempts_remaining (INTEGER)
- max_attempts (INTEGER)
- is_used (BOOLEAN)
- created_at (TIMESTAMPTZ)
- updated_at (TIMESTAMPTZ)
```

#### user_sessions

```sql
- id (UUID, Primary Key)
- user_id (UUID, Foreign Key)
- session_token (VARCHAR)
- refresh_token_id (UUID)
- expires_at (TIMESTAMPTZ)
- ip_address (VARCHAR)
- user_agent (TEXT)
- device_info (JSONB)
- is_active (BOOLEAN)
- created_at (TIMESTAMPTZ)
- last_activity (TIMESTAMPTZ)
- updated_at (TIMESTAMPTZ)
```

#### user_activities

```sql
- id (UUID, Primary Key)
- user_id (UUID, Foreign Key)
- activity_type (VARCHAR)
- description (TEXT)
- ip_address (VARCHAR)
- user_agent (TEXT)
- metadata (JSONB)
- created_at (TIMESTAMPTZ)
```

#### audit_logs

```sql
- id (UUID, Primary Key)
- user_id (UUID, Foreign Key)
- action (VARCHAR)
- resource (VARCHAR)
- resource_id (UUID)
- old_values (JSONB)
- new_values (JSONB)
- ip_address (VARCHAR)
- user_agent (TEXT)
- created_at (TIMESTAMPTZ)
```

#### email_verification_tokens & password_reset_tokens

```sql
- id (UUID, Primary Key)
- user_id (UUID, Foreign Key)
- token (VARCHAR)
- expires_at (TIMESTAMPTZ)
- used (BOOLEAN)
- created_at (TIMESTAMPTZ)
```

## 📧 Email Templates

The application includes comprehensive HTML email templates optimized for various email clients:

### Available Templates

| Template                    | Purpose                                  | Authentication             |
| --------------------------- | ---------------------------------------- | -------------------------- |
| `email_verification.html`   | Account verification during registration | JWT-based URL verification |
| `welcome_email.html`        | Welcome message for new users            | N/A                        |
| `password_reset_email.html` | Password reset requests                  | JWT-based URL verification |
| `security_alert.html`       | Security notifications and alerts        | N/A                        |
| `two_factor_otp.html`       | **Two-factor authentication codes**      | OTP-based verification     |

### Template Features

- **📱 Mobile-responsive** design for all devices
- **📧 Email client compatible** with proper CSS fallbacks
- **🎨 Professional styling** with gradients and modern design
- **🔒 Security-focused** content with clear instructions
- **📊 Device information** tracking for security alerts
- **⏰ Expiration notices** for time-sensitive codes
- **🔗 Fallback links** for email clients that block buttons

### Email Template Variables

#### Common Variables

- `{{ name }}` - User's full name
- `{{ app_name }}` - Application name
- `{{ email }}` - User's email address

#### Verification Templates

- `{{ verification_link }}` - JWT verification URL
- `{{ reset_link }}` - Password reset URL
- `{{ otp_code }}` - One-time password code
- `{{ expiry_hours/minutes }}` - Link/code expiration time

#### Security Templates

- `{{ login_time }}` - When the event occurred
- `{{ ip_address }}` - IP address of the request
- `{{ location }}` - **Real geographic location** (City, Country) - no more "Unknown" placeholders!
- `{{ user_agent }}` - Browser/device information
- `{{ alert_type }}` - Type of security alert
- `{{ details }}` - Specific alert details
- `{{ timestamp }}` - When the alert was generated

## 🔧 Development

### Code Quality

```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Check for security issues
cargo audit
```

### Database Operations

```bash
# Create new migration
diesel migration generate migration_name

# Run migrations
diesel migration run

# Revert migration
diesel migration revert

# Print schema
diesel print-schema
```

## 🔒 Security Features

### Password Security

- **Argon2 Hashing** with configurable parameters
- **Password Strength Validation**
- **Secure Password Generation**
- **JWT-based Password Reset** with secure URL verification

### Authentication Security

- **JWT Token Rotation**
- **Secure Cookie Handling**
- **Rate Limiting** (100 requests/minute)
- **CORS Configuration**
- **Input Validation** and sanitization

### Account Security

- **Account Lockout** after failed attempts
- **Two-Factor Authentication** with role-based requirements
- **Role-Based 2FA Enforcement** (admin, super_admin)
- **Email Verification** required
- **Session Management** with expiration
- **Audit Logging** for compliance
- **Geo-IP Location Tracking** in security events
- **Real User Data in Security Emails** (IP, location, device info)
- **Advanced Security Monitoring** with geographic awareness

### File Upload Security

- **File Type Validation**
- **Size Limits** and validation
- **Path Traversal Protection**
- **Secure File Storage**
- **Thumbnail Generation**

## 🚀 Deployment

### Production Checklist

- [ ] Set strong JWT secrets (32+ characters)
- [ ] Configure production database credentials
- [ ] Set up SMTP server for email functionality
- [ ] Configure proper CORS origins
- [ ] Enable HTTPS in production
- [ ] Configure 2FA role requirements (`APP_TWO_FACTOR__REQUIRED_ROLES`)
- [ ] **Configure Geo-IP settings** (`APP_GEO_IP__ENABLED=true` for location tracking)
- [ ] Set up log aggregation
- [ ] Configure monitoring and alerts
- [ ] Set up database backups
- [ ] Configure rate limiting
- [ ] Set up SSL/TLS certificates
- [ ] **Review security email templates** - ensure they show real user data

### Environment Setup

```bash
# Production configuration
cp config/default.toml config/production.toml

# Edit with production values
nano config/production.toml
```

### Docker Deployment

```dockerfile
FROM rust:1.70-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libpq5 ca-certificates
COPY --from=builder /app/target/release/auth-api /usr/local/bin/
EXPOSE 5000
CMD ["auth-api"]
```

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes**
4. **Format code** (`cargo fmt`)
5. **Submit a pull request**

### Development Guidelines

- Follow Rust best practices and idioms
- Update documentation for API changes
- Use meaningful commit messages
- Follow the existing code architecture

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Actix Web** - Fast, pragmatic HTTP framework
- **Diesel** - Safe, extensible ORM and Query Builder
- **Argon2** - Industry-standard password hashing
- **JWT** - Secure token-based authentication
- **PostgreSQL** - Advanced open source relational database
- **ip-api.com** - Free Geo-IP location service
- **reqwest** - HTTP client for API integrations
- **Rust Community** - Excellent crates and documentation

---

**Made with ❤️ in Rust**
