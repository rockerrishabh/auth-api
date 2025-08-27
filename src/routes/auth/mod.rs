use crate::middleware::AuthMiddleware;
use actix_web::web;

pub mod activity;
pub mod email;
pub mod email_verification;
pub mod login;
pub mod logout;
pub mod otp;
pub mod password_reset;
pub mod password_utils;
pub mod preferences;
pub mod profile;
pub mod refresh;
pub mod register;
pub mod session_management;
pub mod sessions;
pub mod two_factor;
pub mod upload;
pub mod user_management;

pub fn configure_auth_routes(cfg: &mut web::ServiceConfig, auth_middleware: AuthMiddleware) {
    cfg.service(
        web::scope("/auth")
            // Public routes (no authentication required)
            .service(login::login_user)
            .service(register::register_user)
            .service(
                web::scope("/password-reset")
                    .service(password_reset::request_password_reset)
                    .service(password_reset::verify_password_reset_token),
            )
            .service(
                web::scope("/email-verification").service(email_verification::verify_email_link),
            )
            // Protected routes (authentication required)
            .service(
                web::scope("")
                    .wrap(auth_middleware)
                    .service(profile::get_profile)
                    .service(profile::update_profile)
                    .service(profile::change_password)
                    .service(refresh::refresh_token)
                    .service(refresh::refresh_token_dedicated)
                    .service(logout::logout_user)
                    .service(preferences::get_user_preferences)
                    .service(preferences::update_user_preferences)
                    .service(sessions::get_user_sessions)
                    .service(sessions::revoke_session)
                    .service(sessions::revoke_other_sessions)
                    .service(web::scope("/upload").service(upload::upload_avatar))
                    .service(
                        web::scope("/password-reset")
                            .service(password_reset::complete_password_reset),
                    )
                    .service(
                        web::scope("/two-factor")
                            .service(two_factor::setup_two_factor)
                            .service(two_factor::enable_two_factor)
                            .service(two_factor::verify_two_factor)
                            .service(two_factor::disable_two_factor)
                            .service(two_factor::send_login_otp),
                    )
                    .service(
                        web::scope("/user")
                            .service(user_management::update_user_email)
                            .service(user_management::update_user_phone)
                            .service(user_management::update_user_name)
                            .service(user_management::update_user_password)
                            .service(user_management::update_user_avatar)
                            .service(user_management::update_user_verification)
                            .service(user_management::lock_user_account)
                            .service(user_management::get_user_statistics)
                            .service(user_management::search_users),
                    )
                    .service(
                        web::scope("/sessions")
                            .service(session_management::get_current_session)
                            .service(session_management::get_all_user_sessions)
                            .service(session_management::revoke_specific_session)
                            .service(session_management::revoke_other_sessions)
                            .service(session_management::get_session_count)
                            .service(session_management::get_security_alerts),
                    )
                    .service(
                        web::scope("/email")
                            .service(email::send_email)
                            .service(email::send_welcome_email)
                            .service(email::send_security_alert_email)
                            .service(email::test_otp_email),
                    )
                    .service(
                        web::scope("/otp")
                            .service(otp::create_otp)
                            .service(otp::verify_otp)
                            .service(otp::get_otp)
                            .service(otp::cleanup_expired_otps)
                            .service(otp::demo_otp_methods),
                    )
                    .service(
                        web::scope("/password")
                            .service(password_utils::validate_password_strength)
                            .service(password_utils::generate_secure_password)
                            .service(password_utils::hash_password)
                            .service(password_utils::hash_and_validate_password),
                    )
                    .service(
                        web::scope("/activity")
                            .service(activity::log_user_activity)
                            .service(activity::get_my_activities)
                            .service(activity::get_recent_activities)
                            .service(activity::get_activity_summary)
                            .service(activity::get_logins_today)
                            .service(activity::get_logins_week)
                            .service(activity::get_logins_month)
                            .service(activity::get_failed_login_attempts)
                            .service(activity::get_user_audit_logs),
                    ),
            ),
    );
}
