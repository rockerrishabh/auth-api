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
    bundle_analyses (id) {
        id -> Uuid,
        total_size_bytes -> Int8,
        gzipped_size_bytes -> Int8,
        chunks -> Int4,
        largest_chunks -> Jsonb,
        unused_dependencies -> Jsonb,
        optimization_opportunities -> Jsonb,
        created_at -> Timestamptz,
    }
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
    performance_issues (id) {
        id -> Uuid,
        #[max_length = 100]
        issue_type -> Varchar,
        #[max_length = 50]
        severity -> Varchar,
        #[max_length = 255]
        title -> Varchar,
        description -> Text,
        impact -> Text,
        recommendation -> Text,
        #[max_length = 255]
        estimated_savings -> Varchar,
        #[max_length = 50]
        status -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
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
    render_metrics (id) {
        id -> Uuid,
        #[max_length = 255]
        component_name -> Varchar,
        render_count -> Int4,
        average_render_time_ms -> Int8,
        last_render_time_ms -> Int8,
        memory_usage_mb -> Numeric,
        optimization_score -> Int4,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    service_health (id) {
        id -> Uuid,
        #[max_length = 255]
        service_name -> Varchar,
        #[max_length = 50]
        status -> Varchar,
        response_time_ms -> Int8,
        last_check -> Timestamptz,
        #[max_length = 500]
        endpoint -> Varchar,
        error_message -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    system_metrics (id) {
        id -> Uuid,
        cpu_usage -> Numeric,
        memory_usage -> Numeric,
        disk_usage -> Numeric,
        network_usage -> Numeric,
        response_time_ms -> Int8,
        uptime_seconds -> Int8,
        active_users -> Int4,
        error_rate -> Numeric,
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
    test_performance_metrics (id) {
        id -> Uuid,
        response_time_ms -> Int8,
        throughput_rps -> Int8,
        error_rate_percent -> Numeric,
        cpu_usage_percent -> Numeric,
        memory_usage_percent -> Numeric,
        active_connections -> Int8,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    test_results (id) {
        id -> Uuid,
        test_suite_id -> Uuid,
        #[max_length = 255]
        name -> Varchar,
        #[max_length = 50]
        status -> Varchar,
        duration_ms -> Int8,
        timestamp -> Timestamptz,
        error -> Nullable<Text>,
        #[max_length = 100]
        category -> Varchar,
        #[max_length = 50]
        priority -> Varchar,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    test_suites (id) {
        id -> Uuid,
        #[max_length = 255]
        name -> Varchar,
        total_tests -> Int4,
        passed_tests -> Int4,
        failed_tests -> Int4,
        running_tests -> Int4,
        duration_ms -> Int8,
        last_run -> Timestamptz,
        #[max_length = 50]
        status -> Varchar,
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
diesel::joinable!(test_results -> test_suites (test_suite_id));
diesel::joinable!(user_activity_logs -> users (user_id));
diesel::joinable!(user_role_assignments -> user_roles (role_id));
diesel::joinable!(user_sessions -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    bundle_analyses,
    email_verification_tokens,
    otps,
    password_reset_tokens,
    performance_issues,
    refresh_tokens,
    render_metrics,
    service_health,
    system_metrics,
    system_settings,
    test_performance_metrics,
    test_results,
    test_suites,
    user_activity_logs,
    user_permissions,
    user_role_assignments,
    user_roles,
    user_sessions,
    users,
);
