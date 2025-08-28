# Account Locking Issue - Fix Documentation

## Problem Description

The backend was experiencing an issue where user accounts were getting locked during login attempts, even when the accounts were not actually locked due to failed password attempts. This was causing legitimate users to be unable to access their accounts.

## Root Cause Analysis

The issue was in the authentication logic in `src/services/core/auth.rs`:

1. **Confusing Logic Flow**: The `can_login()` method was checking both account status AND lock status, but the account status check was too restrictive.

2. **Account Status vs Lock Status**: Users with `account_status = 'pending_verification'` were being treated as locked accounts, even though they weren't actually locked due to failed attempts.

3. **Failed Login Counter**: The system was incrementing failed login attempts for accounts that weren't actually locked, leading to unnecessary lockouts.

## Changes Made

### 1. Fixed Authentication Logic (`src/services/core/auth.rs`)

- **Separated Lock Check from Account Status Check**: Now checks if account is actually locked first, before checking email verification status.
- **Improved Error Handling**: Better distinction between locked accounts and unverified accounts.
- **Reset Failed Attempts**: Failed login attempts are now reset on successful password verification, not just on successful login.

### 2. Enhanced User Model (`src/db/models.rs`)

- **Added `can_attempt_login()` method**: Checks only if account is locked, regardless of verification status.
- **Improved `can_login()` method**: More specific about what it checks.
- **Better Method Documentation**: Clearer purpose for each method.

### 3. Enhanced User Service (`src/services/core/user.rs`)

- **Added `unlock_user_account()` method**: Allows admins to manually unlock specific accounts.
- **Added `unlock_expired_accounts()` method**: Automatically unlocks accounts that are past their lockout duration.
- **Better Account Management**: More granular control over account locking/unlocking.

### 4. New Admin Endpoints (`src/routes/auth/user_management.rs`)

- **`POST /v1/auth/user/unlock-account`**: Unlock a specific user account.
- **`POST /v1/auth/user/unlock-expired-accounts`**: Unlock all expired lockouts.
- **`POST /v1/auth/user/verify-email`**: Manually verify a user's email (for testing).

## Current Security Settings

The system uses these default security settings (configurable via environment variables):

- **`APP_SECURITY__MAX_FAILED_ATTEMPTS`**: 5 (default: 5)
- **`APP_SECURITY__LOCKOUT_DURATION`**: 900 seconds (15 minutes)
- **`APP_SECURITY__SESSION_TIMEOUT`**: 86400 seconds (24 hours)

## How to Prevent This Issue

### 1. Monitor Account Status

Regularly check for accounts stuck in `pending_verification` status:

```sql
SELECT username, email, account_status, failed_login_attempts, locked_until
FROM users
WHERE account_status = 'pending_verification';
```

### 2. Monitor Failed Login Attempts

Check for accounts with high failed login attempts:

```sql
SELECT username, email, failed_login_attempts, locked_until
FROM users
WHERE failed_login_attempts > 0;
```

### 3. Use Admin Endpoints

- **Unlock Expired Accounts**: Run `/v1/auth/user/unlock-expired-accounts` periodically
- **Manual Unlock**: Use `/v1/auth/user/unlock-account` for specific cases
- **Email Verification**: Use `/v1/auth/user/verify-email` for testing

### 4. Environment Variables

Ensure these are set correctly in your `.env` file:

```bash
APP_SECURITY__MAX_FAILED_ATTEMPTS=5
APP_SECURITY__LOCKOUT_DURATION=900
APP_SECURITY__SESSION_TIMEOUT=86400
```

## Testing the Fix

1. **Compile the Application**: `cargo check` should pass without errors
2. **Test Login Flow**: Users should now be able to login without getting locked
3. **Test Failed Attempts**: After 5 failed attempts, accounts should lock for 15 minutes
4. **Test Admin Endpoints**: Verify admin can unlock accounts and verify emails

## Monitoring and Maintenance

### Daily Checks

- Monitor failed login attempts
- Check for locked accounts
- Review activity logs for lockout events

### Weekly Tasks

- Run unlock expired accounts endpoint
- Review user verification status
- Check security metrics

### Monthly Tasks

- Review security configuration
- Analyze login patterns
- Update security policies if needed

## Conclusion

The account locking issue has been resolved by:

1. **Separating concerns** between account locking and account verification
2. **Improving error handling** to provide clearer feedback
3. **Adding admin tools** to manage account states
4. **Better documentation** of the authentication flow

Users should now be able to login successfully without experiencing unnecessary account lockouts, while maintaining the security benefits of the failed attempt lockout system.
