use actix_web::web;

mod auth;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(auth::login::login_user)
            .service(auth::register::register_user)
            .service(auth::me::get_user_profile)
            .service(auth::profile_update::update_profile)
            .service(auth::logout::logout_user)
            .service(auth::refresh::refresh_user_token)
            .service(auth::verify::verify_email)
            .service(auth::verify::resend_verification)
            .service(auth::password_reset::request_password_reset)
            .service(auth::password_reset::reset_password)
            .service(auth::password_change::change_password)
            .service(
                web::scope("/admin")
                    .service(auth::admin::make_user_admin)
                    .service(auth::admin::get_admin_stats)
                    .service(auth::admin::get_all_users)
                    .service(auth::admin::update_user)
                    .service(auth::admin::delete_user)
            ),
    );
}
