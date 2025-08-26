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
                match AuthMiddleware::new(config.clone()) {
                    Ok(auth_middleware) => {
                        auth::configure_auth_routes(cfg, auth_middleware);
                    }
                    Err(e) => {
                        panic!("Failed to create auth middleware for auth routes: {}", e);
                    }
                }
            })
            .configure(|cfg| {
                // Create auth middleware for admin routes
                match AuthMiddleware::new(config.clone()) {
                    Ok(auth_middleware) => {
                        admin::configure_admin_routes(
                            cfg,
                            auth_middleware,
                            db_pool,
                            config.clone(),
                        );
                    }
                    Err(e) => {
                        panic!("Failed to create auth middleware for admin routes: {}", e);
                    }
                }
            })
            .service(
                web::scope("")
                    .service(health::health_check)
                    .service(health::detailed_health_check),
            ),
    );
}
