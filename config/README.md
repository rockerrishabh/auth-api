# Configuration

This directory contains configuration files for the Auth API.

## Configuration Files

### `default.toml`

Base configuration file with default values. **Required** for the application to start.

### `development.toml`

Development-specific overrides. Loaded when `ENVIRONMENT=development`.

### `local.toml`

Personal local development overrides. **Never commit this file** as it may contain sensitive data like real email credentials.

## Configuration Priority

1. **Environment Variables** (highest priority) - prefixed with `APP_`
2. `config/local.toml` - personal overrides
3. `config/{environment}.toml` - environment-specific
4. `config/default.toml` - base configuration (lowest priority)

## Setting Up

### 1. Basic Setup

```bash
# Copy and edit the default configuration
cp config/default.toml config/local.toml
# Edit config/local.toml with your settings
```

### 2. Using Environment Variables

```bash
export ENVIRONMENT=development
export APP_DATABASE__URL="postgresql://user:pass@localhost/db"
export APP_JWT__SECRET="your-secret-key"
```

### 3. For Production

```bash
export ENVIRONMENT=production
# Create config/production.toml with production settings
```

## Security Notes

- Never commit `config/local.toml` to version control
- Keep JWT secrets secure and randomly generated
- Use strong passwords for email accounts
- Configure production database credentials properly

## Configuration Sections

- **Application**: Host, port, environment
- **Database**: PostgreSQL connection settings
- **JWT**: Token secrets and expiry times
- **Email**: SMTP server configuration
- **Security**: Password hashing, rate limiting, lockout
- **Upload**: File upload settings and limits
