use crate::middleware::logging::LoggingMiddleware;
use actix_cors::Cors;
use actix_web::http::header;
use actix_web::middleware::Compress;
use actix_web::middleware::NormalizePath;
use actix_web::{web, App, HttpServer};
use tracing::info;

mod config;
mod db;
mod error;
mod middleware;
mod routes;
mod services;

use crate::config::AppConfig;
use crate::db::establish_connection;
use crate::middleware::RateLimitMiddleware;
use crate::routes::configure_routes_simple;
use actix_files as fs;
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = AppConfig::new().expect("Failed to load configuration");

    info!("Starting auth service on {}:{}", config.host, config.port);

    // Establish database connection
    let db_pool = establish_connection(&config.database)
        .await
        .expect("Failed to establish database connection");

    info!("Database connection established successfully");

    // Create HTTP server
    let config_data = web::Data::new(config.clone());
    let db_pool_data = web::Data::new(db_pool.clone());

    HttpServer::new(move || {
        App::new()
            .app_data(config_data.clone())
            .app_data(db_pool_data.clone())
            .wrap({
                let config_data_clone = config_data.clone();
                Cors::default()
                    .allowed_origin_fn(move |origin, _req_head| {
                        let origin_str = origin.to_str().unwrap_or("");
                        let frontend_url = &config_data_clone.frontend_url;

                        // Allow localhost on any port for development
                        origin_str.starts_with("http://localhost:") ||
                        origin_str.starts_with("https://localhost:") ||
                        // Allow the configured frontend URL
                        origin_str == frontend_url ||
                        // Allow the frontend URL with different protocol (http/https)
                        (frontend_url.starts_with("http://") && origin_str == frontend_url.replace("http://", "https://")) ||
                        (frontend_url.starts_with("https://") && origin_str == frontend_url.replace("https://", "http://"))
                    })
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
                    .allowed_headers(vec![
                        header::AUTHORIZATION,
                        header::ACCEPT,
                        header::CONTENT_TYPE,
                        header::ORIGIN,
                        "X-Requested-With".parse().unwrap(),
                        "X-Total-Count".parse().unwrap(),
                    ])
                    .expose_headers(vec![
                        header::AUTHORIZATION,
                        header::CONTENT_TYPE,
                        "X-Total-Count".parse().unwrap(),
                    ])
                    .supports_credentials()
                    .max_age(3600)
            })
            .wrap(LoggingMiddleware::new())
            .wrap(Compress::default())
            .wrap(NormalizePath::trim())
            .wrap(RateLimitMiddleware::new(100, Duration::from_secs(60))) // 100 requests per minute
            .service(
                fs::Files::new("/static", &config_data.upload.dir)
                    .show_files_listing()
                    .use_last_modified(true),
            )
            .configure(|cfg| {
                configure_routes_simple(
                    cfg,
                    config_data.as_ref().clone(),
                    db_pool_data.as_ref().clone(),
                )
            })
    })
    .bind(format!("{}:{}", config.host, config.port))?
    .run()
    .await
}
