-- Revert to old enum types without underscores
-- This migration reverses the changes made in the up migration

-- First, drop indexes that reference enum columns
DROP INDEX IF EXISTS idx_users_role;

DROP INDEX IF EXISTS idx_users_account_status;

DROP INDEX IF EXISTS idx_otps_type;

-- Temporarily change the column types to text to avoid enum constraints
ALTER TABLE users ALTER COLUMN role TYPE text;

ALTER TABLE user_roles ALTER COLUMN name TYPE text;

ALTER TABLE users ALTER COLUMN account_status TYPE text;

ALTER TABLE otps ALTER COLUMN otp_type TYPE text;

-- Update any existing data back to old format without underscores
UPDATE users SET role = 'superadmin' WHERE role = 'super_admin';

UPDATE users
SET
    account_status = 'pendingverification'
WHERE
    account_status = 'pending_verification';

UPDATE otps
SET
    otp_type = 'emailverification'
WHERE
    otp_type = 'email_verification';

UPDATE otps
SET
    otp_type = 'passwordreset'
WHERE
    otp_type = 'password_reset';

UPDATE otps
SET
    otp_type = 'loginverification'
WHERE
    otp_type = 'login_verification';

UPDATE otps SET otp_type = 'twofactor' WHERE otp_type = 'two_factor';

UPDATE otps
SET
    otp_type = 'phoneverification'
WHERE
    otp_type = 'phone_verification';

UPDATE user_roles SET name = 'superadmin' WHERE name = 'super_admin';

-- Drop the new enum types completely
DROP TYPE IF EXISTS user_role CASCADE;

DROP TYPE IF EXISTS account_status CASCADE;

DROP TYPE IF EXISTS otp_type CASCADE;

-- Recreate the old enum types without underscores
CREATE TYPE user_role AS ENUM ('superadmin', 'admin', 'moderator', 'user', 'guest');

CREATE TYPE account_status AS ENUM ('active', 'suspended', 'banned', 'pendingverification', 'deactivated');

CREATE TYPE otp_type AS ENUM ('emailverification', 'passwordreset', 'loginverification', 'twofactor', 'phoneverification');

-- Change the columns back to use the old enum types
ALTER TABLE users ALTER COLUMN role TYPE user_role USING role::user_role;

ALTER TABLE user_roles ALTER COLUMN name TYPE user_role USING name::user_role;

ALTER TABLE users ALTER COLUMN account_status TYPE account_status USING account_status::account_status;

ALTER TABLE otps ALTER COLUMN otp_type TYPE otp_type USING otp_type::otp_type;

-- Recreate the indexes
CREATE INDEX idx_users_role ON users (role);

CREATE INDEX idx_users_account_status ON users (account_status);

CREATE INDEX idx_otps_type ON otps (otp_type);