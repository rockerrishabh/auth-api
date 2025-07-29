use actix_web::web;

mod auth;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(auth::login::login_user)
            .service(auth::register::register_user)
            .service(auth::me::user)
            .service(auth::logout::logout_user)
            .service(auth::refresh::refresh_token)
            .service(auth::verify::verify_user)
            .service(auth::reset::reset_password),
    );
}
