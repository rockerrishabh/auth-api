use crate::config::AppConfig;
use crate::db::DbPool;
use crate::middleware::AuthMiddleware;
use actix_web::web;

pub mod admin;
pub mod auth;
pub mod health;



pub fn configure_routes_simple(cfg: &mut web::ServiceConfig, config: AppConfig, db_pool: DbPool) {
    cfg.service(
        web::scope("/api/v1")
            .configure(|cfg| {
                // Create auth middleware for auth routes
                let auth_middleware = AuthMiddleware::new(config.clone())
                    .expect("Failed to create auth middleware for auth routes");
                auth::configure_auth_routes(cfg, auth_middleware);
            })
            .configure(|cfg| {
                // Create auth middleware for admin routes
                let auth_middleware = AuthMiddleware::new(config.clone())
                    .expect("Failed to create auth middleware for admin routes");
                admin::configure_admin_routes(cfg, auth_middleware, db_pool, config.clone());
            })
            .service(
                web::scope("")
                    .service(health::health_check)
                    .service(health::detailed_health_check),
            ),
    );
}
