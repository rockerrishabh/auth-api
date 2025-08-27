-- Create new enum types with correct underscore values
-- This migration creates fresh enum types to avoid dependency conflicts

-- First, drop indexes that reference enum columns
DROP INDEX IF EXISTS idx_users_role;

DROP INDEX IF EXISTS idx_users_account_status;

DROP INDEX IF EXISTS idx_otps_type;

-- Temporarily change the column types to text to avoid enum constraints
ALTER TABLE users ALTER COLUMN role TYPE text;

ALTER TABLE user_roles ALTER COLUMN name TYPE text;

ALTER TABLE users ALTER COLUMN account_status TYPE text;

ALTER TABLE otps ALTER COLUMN otp_type TYPE text;

-- Update any existing data to use new format with underscores
UPDATE users SET role = 'super_admin' WHERE role = 'superadmin';

UPDATE users
SET
    account_status = 'pending_verification'
WHERE
    account_status = 'pendingverification';

UPDATE otps
SET
    otp_type = 'email_verification'
WHERE
    otp_type = 'emailverification';

UPDATE otps
SET
    otp_type = 'password_reset'
WHERE
    otp_type = 'passwordreset';

UPDATE otps
SET
    otp_type = 'login_verification'
WHERE
    otp_type = 'loginverification';

UPDATE otps SET otp_type = 'two_factor' WHERE otp_type = 'twofactor';

UPDATE otps
SET
    otp_type = 'phone_verification'
WHERE
    otp_type = 'phoneverification';

UPDATE user_roles SET name = 'super_admin' WHERE name = 'superadmin';

-- Drop the old enum types completely
DROP TYPE IF EXISTS user_role CASCADE;

DROP TYPE IF EXISTS account_status CASCADE;

DROP TYPE IF EXISTS otp_type CASCADE;

-- Create new enum types with correct values
CREATE TYPE user_role AS ENUM ('super_admin', 'admin', 'moderator', 'user', 'guest');

CREATE TYPE account_status AS ENUM ('active', 'suspended', 'banned', 'pending_verification', 'deactivated');

CREATE TYPE otp_type AS ENUM ('email_verification', 'password_reset', 'login_verification', 'two_factor', 'phone_verification');

-- Change the columns to use the new enum types
ALTER TABLE users ALTER COLUMN role TYPE user_role USING role::user_role;

ALTER TABLE user_roles ALTER COLUMN name TYPE user_role USING name::user_role;

ALTER TABLE users ALTER COLUMN account_status TYPE account_status USING account_status::account_status;

ALTER TABLE otps ALTER COLUMN otp_type TYPE otp_type USING otp_type::otp_type;

-- Recreate the indexes
CREATE INDEX idx_users_role ON users (role);

CREATE INDEX idx_users_account_status ON users (account_status);

CREATE INDEX idx_otps_type ON otps (otp_type);