# Auth API - Rust Backend

A secure authentication API built with Rust, Actix Web, and PostgreSQL.

## Features

- User registration with email verification
- Secure login with JWT tokens
- Refresh token rotation
- Password reset functionality
- Email verification system
- Role-based access control
- Image upload and processing
- Secure password hashing with Argon2
- Comprehensive error handling

## Prerequisites

- Rust 1.70+
- PostgreSQL 12+
- SMTP server access

## Setup

1. **Clone and navigate to the project:**
   ```bash
   cd auth-api
   ```

2. **Install dependencies:**
   ```bash
   cargo build
   ```

3. **Set up environment variables:**
   ```bash
   cp env.example .env
   # Edit .env with your actual values
   ```

4. **Set up the database:**
   ```bash
   # Create a PostgreSQL database
   createdb auth_db
   
   # Run migrations
   diesel migration run
   ```

5. **Run the application:**
   ```bash
   cargo run
   ```

## Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET`: Secret key for JWT signing
- `JWT_EXPIRES_IN`: JWT expiration time in seconds
- `SERVER_DOMAIN`: Your server domain
- `FRONTEND_URL`: Your frontend application URL
- `SMTP_*`: SMTP server configuration
- `UPLOAD_*`: File upload configuration

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/refresh` - Refresh access token
- `GET /auth/me` - Get user profile
- `GET /auth/verify` - Verify email address
- `POST /auth/resend-verification` - Resend verification email

### File Upload
- Static files are served from `/static` endpoint

## Database Schema

The application uses the following main tables:
- `users` - User accounts and profiles
- `email_verification_tokens` - Email verification tokens
- `password_reset_tokens` - Password reset tokens
- `refresh_tokens` - JWT refresh tokens

## Security Features

- Password hashing with Argon2 (winner of Password Hashing Competition)
- JWT token rotation
- Secure cookie handling
- CORS configuration
- Input validation and sanitization
- Rate limiting (can be added)

## Development

### Running Tests
```bash
cargo test
```

### Database Migrations
```bash
# Create new migration
diesel migration generate migration_name

# Run migrations
diesel migration run

# Revert migrations
diesel migration revert
```

### Code Formatting
```bash
cargo fmt
```

### Linting
```bash
cargo clippy
```

## Project Structure

```
src/
├── config/          # Configuration management
├── db/             # Database models and schema
├── mail/           # Email service
├── routes/         # API route handlers
├── utils/          # Utility functions
├── lib.rs          # Library exports
└── main.rs         # Application entry point
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License
