-- Create custom ENUM types
CREATE TYPE user_role AS ENUM ('superadmin', 'admin', 'moderator', 'user', 'guest');

CREATE TYPE account_status AS ENUM ('active', 'suspended', 'banned', 'pendingverification', 'deactivated');

CREATE TYPE otp_type AS ENUM ('emailverification', 'passwordreset', 'loginverification', 'twofactor', 'phoneverification');

-- Create users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    name VARCHAR(100) NOT NULL,
    role user_role NOT NULL DEFAULT 'user',
    email_verified BOOLEAN NOT NULL DEFAULT false,
    email_verified_at TIMESTAMPTZ,
    phone VARCHAR(20),
    phone_verified BOOLEAN NOT NULL DEFAULT false,
    two_factor_enabled BOOLEAN NOT NULL DEFAULT false,
    two_factor_secret VARCHAR(255),
    last_login_at TIMESTAMPTZ,
    last_login_ip VARCHAR(45),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    account_status account_status NOT NULL DEFAULT 'pendingverification',
    avatar VARCHAR(255),
    avatar_thumbnail VARCHAR(255),
    preferences JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Create OTPs table
CREATE TABLE otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    otp_type otp_type NOT NULL,
    code VARCHAR(10) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts_remaining INTEGER NOT NULL DEFAULT 3,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    is_used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create user_sessions table
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    device_info JSONB,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_activity TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create user_activity_logs table
CREATE TABLE user_activity_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    activity_type VARCHAR(100) NOT NULL,
    description VARCHAR(500) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create refresh_tokens table
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create password_reset_tokens table
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create email_verification_tokens table
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create user_roles table
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(500),
    permissions JSONB NOT NULL DEFAULT '{}',
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create user_permissions table
CREATE TABLE user_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID REFERENCES users (id),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Create user_role_assignments table
CREATE TABLE user_role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES user_roles (id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users (id),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE system_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    setting_type VARCHAR(50) NOT NULL,
    description VARCHAR(500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_users_username ON users (username);

CREATE INDEX idx_users_email ON users (email);

CREATE INDEX idx_users_role ON users (role);

CREATE INDEX idx_users_account_status ON users (account_status);

CREATE INDEX idx_users_created_at ON users (created_at);

CREATE INDEX idx_users_deleted_at ON users (deleted_at);

CREATE INDEX idx_otps_user_id ON otps (user_id);

CREATE INDEX idx_otps_type ON otps (otp_type);

CREATE INDEX idx_otps_expires_at ON otps (expires_at);

CREATE INDEX idx_otps_code ON otps (code);

CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id);

CREATE INDEX idx_user_sessions_token ON user_sessions (session_token);

CREATE INDEX idx_user_sessions_expires_at ON user_sessions (expires_at);

CREATE INDEX idx_user_activity_logs_user_id ON user_activity_logs (user_id);

CREATE INDEX idx_user_activity_logs_activity_type ON user_activity_logs (activity_type);

CREATE INDEX idx_user_activity_logs_created_at ON user_activity_logs (created_at);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);

CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);

CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);

CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens (user_id);

CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens (expires_at);

CREATE INDEX idx_user_permissions_user_id ON user_permissions (user_id);

CREATE INDEX idx_user_permissions_permission ON user_permissions (permission);

CREATE INDEX idx_user_role_assignments_user_id ON user_role_assignments (user_id);

CREATE INDEX idx_user_role_assignments_role_id ON user_role_assignments (role_id);

-- Create index for faster lookups
CREATE INDEX idx_system_settings_key ON system_settings (setting_key);

-- Insert default user roles
INSERT INTO
    user_roles (
        name,
        description,
        permissions,
        is_default
    )
VALUES (
        'superadmin',
        'Super Administrator with full system access',
        '{"all": true}',
        false
    ),
    (
        'admin',
        'Administrator with management access',
        '{"users": true, "content": true, "settings": true}',
        false
    ),
    (
        'moderator',
        'Moderator with content management access',
        '{"content": true, "users": {"read": true}}',
        false
    ),
    (
        'user',
        'Regular user with basic access',
        '{"profile": true, "content": {"read": true}}',
        true
    ),
    (
        'guest',
        'Guest user with limited access',
        '{"content": {"read": true}}',
        false
    );

-- Insert default super admin user (password: admin123)
INSERT INTO
    users (
        username,
        email,
        password_hash,
        name,
        role,
        email_verified,
        account_status
    )
VALUES (
        'admin',
        'admin@example.com',
        '$argon2id$v=19$m=65536,t=3,p=1$YWRtaW4xMjM$hashed_password_here',
        'Super Admin',
        'superadmin',
        true,
        'active'
    );

-- Insert default system settings
INSERT INTO
    system_settings (
        setting_key,
        setting_value,
        setting_type,
        description
    )
VALUES (
        'app_name',
        'Advanced Authentication System',
        'string',
        'Application name displayed to users'
    ),
    (
        'app_description',
        'Advanced Authentication System',
        'string',
        'Application description'
    ),
    (
        'maintenance_mode',
        'false',
        'boolean',
        'Whether the system is in maintenance mode'
    ),
    (
        'registration_enabled',
        'true',
        'boolean',
        'Whether new user registration is allowed'
    ),
    (
        'email_verification_required',
        'true',
        'boolean',
        'Whether email verification is required'
    ),
    (
        'two_factor_required',
        'false',
        'boolean',
        'Whether 2FA is required for all users'
    );

-- Set up Diesel's built-in updated_at functionality for tables with updated_at field
SELECT diesel_manage_updated_at ('users');

SELECT diesel_manage_updated_at ('otps');

SELECT diesel_manage_updated_at ('user_sessions');

SELECT diesel_manage_updated_at ('user_roles');

SELECT diesel_manage_updated_at ('system_settings');