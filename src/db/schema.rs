// @generated automatically by Diesel CLI.

pub mod sql_types {
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
        created_at -> Timestamptz,
        used -> Bool,
    }
}

diesel::table! {
    password_reset_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        used -> Bool,
    }
}

diesel::table! {
    refresh_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        revoked -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::UserRole;

    users (id) {
        id -> Uuid,
        #[max_length = 255]
        email -> Varchar,
        #[max_length = 255]
        password_hash -> Nullable<Varchar>,
        #[max_length = 100]
        name -> Varchar,
        role -> UserRole,
        #[max_length = 255]
        avatar -> Nullable<Varchar>,
        #[max_length = 255]
        avatar_thumbnail -> Nullable<Varchar>,
        email_verified -> Bool,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(email_verification_tokens -> users (user_id));
diesel::joinable!(password_reset_tokens -> users (user_id));
diesel::joinable!(refresh_tokens -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    email_verification_tokens,
    password_reset_tokens,
    refresh_tokens,
    users,
);
