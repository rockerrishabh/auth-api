// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "account_status"))]
    pub struct AccountStatus;

    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "otp_type"))]
    pub struct OtpType;

    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "user_role"))]
    pub struct UserRole;
}

diesel::table! {
    email_verification_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        is_used -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::OtpType;

    otps (id) {
        id -> Uuid,
        user_id -> Uuid,
        otp_type -> OtpType,
        #[max_length = 10]
        code -> Varchar,
        expires_at -> Timestamptz,
        attempts_remaining -> Int4,
        max_attempts -> Int4,
        is_used -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    password_reset_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        is_used -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    refresh_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        is_revoked -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    system_settings (id) {
        id -> Uuid,
        #[max_length = 100]
        setting_key -> Varchar,
        setting_value -> Text,
        #[max_length = 50]
        setting_type -> Varchar,
        #[max_length = 500]
        description -> Nullable<Varchar>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_activity_logs (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 100]
        activity_type -> Varchar,
        #[max_length = 500]
        description -> Varchar,
        #[max_length = 45]
        ip_address -> Nullable<Varchar>,
        #[max_length = 500]
        user_agent -> Nullable<Varchar>,
        metadata -> Nullable<Jsonb>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_permissions (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 100]
        permission -> Varchar,
        granted_at -> Timestamptz,
        granted_by -> Nullable<Uuid>,
        expires_at -> Nullable<Timestamptz>,
        is_active -> Bool,
    }
}

diesel::table! {
    user_role_assignments (id) {
        id -> Uuid,
        user_id -> Uuid,
        role_id -> Uuid,
        assigned_at -> Timestamptz,
        assigned_by -> Nullable<Uuid>,
        expires_at -> Nullable<Timestamptz>,
        is_active -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::UserRole;

    user_roles (id) {
        id -> Uuid,
        name -> UserRole,
        #[max_length = 500]
        description -> Nullable<Varchar>,
        permissions -> Jsonb,
        is_default -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        session_token -> Varchar,
        expires_at -> Timestamptz,
        #[max_length = 45]
        ip_address -> Nullable<Varchar>,
        #[max_length = 500]
        user_agent -> Nullable<Varchar>,
        device_info -> Nullable<Jsonb>,
        is_active -> Bool,
        last_activity -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::UserRole;
    use super::sql_types::AccountStatus;

    users (id) {
        id -> Uuid,
        #[max_length = 50]
        username -> Varchar,
        #[max_length = 255]
        email -> Varchar,
        #[max_length = 255]
        password_hash -> Nullable<Varchar>,
        #[max_length = 100]
        name -> Varchar,
        role -> UserRole,
        email_verified -> Bool,
        email_verified_at -> Nullable<Timestamptz>,
        #[max_length = 20]
        phone -> Nullable<Varchar>,
        phone_verified -> Bool,
        two_factor_enabled -> Bool,
        #[max_length = 255]
        two_factor_secret -> Nullable<Varchar>,
        last_login_at -> Nullable<Timestamptz>,
        #[max_length = 45]
        last_login_ip -> Nullable<Varchar>,
        failed_login_attempts -> Int4,
        locked_until -> Nullable<Timestamptz>,
        account_status -> AccountStatus,
        #[max_length = 255]
        avatar -> Nullable<Varchar>,
        #[max_length = 255]
        avatar_thumbnail -> Nullable<Varchar>,
        preferences -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(email_verification_tokens -> users (user_id));
diesel::joinable!(otps -> users (user_id));
diesel::joinable!(password_reset_tokens -> users (user_id));
diesel::joinable!(refresh_tokens -> users (user_id));
diesel::joinable!(user_activity_logs -> users (user_id));
diesel::joinable!(user_role_assignments -> user_roles (role_id));
diesel::joinable!(user_sessions -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    email_verification_tokens,
    otps,
    password_reset_tokens,
    refresh_tokens,
    system_settings,
    user_activity_logs,
    user_permissions,
    user_role_assignments,
    user_roles,
    user_sessions,
    users,
);
