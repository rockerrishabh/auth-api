-- Drop tables in reverse order (respecting foreign key constraints)
DROP TABLE IF EXISTS user_role_assignments;

DROP TABLE IF EXISTS user_permissions;

DROP TABLE IF EXISTS user_roles;

DROP TABLE IF EXISTS email_verification_tokens;

DROP TABLE IF EXISTS password_reset_tokens;

DROP TABLE IF EXISTS refresh_tokens;

DROP TABLE IF EXISTS user_activity_logs;

DROP TABLE IF EXISTS user_sessions;

DROP TABLE IF EXISTS otps;

DROP TABLE IF EXISTS users;

-- Drop custom ENUM types
DROP TYPE IF EXISTS otp_type;

DROP TYPE IF EXISTS account_status;

DROP TYPE IF EXISTS user_role;

DROP TABLE IF EXISTS system_settings;