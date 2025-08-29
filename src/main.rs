use crate::middleware::logging::LoggingMiddleware;
use crate::services::utils::geoip::GeoIPService;
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
use std::path::PathBuf;
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    match dotenv::dotenv() {
        Ok(path) => info!("Loaded environment file: {:?}", path),
        Err(_) => info!("No .env file found, using system environment variables"),
    }

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = match AppConfig::new() {
        Ok(config) => {
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            eprintln!("Make sure all required environment variables are set with APP_ prefix");
            eprintln!("Required variables:");
            eprintln!("  APP_ENVIRONMENT=production");
            eprintln!("  APP_DATABASE__URL=postgresql://...");
            eprintln!("  APP_JWT__SECRET=your-secret");
            eprintln!("  APP_EMAIL__SMTP_HOST=your-smtp");
            eprintln!("  APP_EMAIL__SMTP_USERNAME=your-email");
            eprintln!("  APP_EMAIL__SMTP_PASSWORD=your-password");

            // Debug: Print all APP_ environment variables
            eprintln!("\nDebug: Current APP_ environment variables:");
            for (key, value) in std::env::vars() {
                if key.starts_with("APP_") {
                    eprintln!("  {}={}", key, value);
                }
            }
            eprintln!("");

            panic!("Configuration loading failed: {}", e);
        }
    };

    info!("Starting auth service on {}:{}", config.host, config.port);
    info!("Database URL: {}", config.database.url);
    info!("Environment: {}", config.environment);
    info!(
        "Email SMTP: {}:{}",
        config.email.smtp_host, config.email.smtp_port
    );

    // Establish database connection
    info!("Attempting to connect to database...");
    let db_pool = match establish_connection(&config.database).await {
        Ok(pool) => {
            info!("Database connection established successfully");
            pool
        }
        Err(e) => {
            eprintln!("Database connection failed: {}", e);
            eprintln!("Database URL being used: {}", config.database.url);
            eprintln!("Please check:");
            eprintln!("1. APP_DATABASE__URL is set correctly");
            eprintln!("2. Database credentials are valid");
            eprintln!("3. Database server is running and accessible");
            panic!("Database connection failed: {}", e);
        }
    };

    // Initialize GeoIP service
    let geo_ip_service = if config.geo_ip.enabled {
        info!(
            "GeoIP service enabled with endpoint: {}",
            config.geo_ip.api_endpoint
        );
        if config.geo_ip.cache_enabled {
            info!("GeoIP caching enabled");
        }
        info!(
            "GeoIP timeout set to {} seconds",
            config.geo_ip.timeout_seconds
        );
        Some(
            GeoIPService::new_with_timeout(
                config.geo_ip.cache_enabled,
                config.geo_ip.timeout_seconds,
            )
            .with_endpoint(config.geo_ip.api_endpoint.clone()),
        )
    } else {
        info!("GeoIP service disabled");
        None
    };
    let geo_ip_data = web::Data::new(geo_ip_service);

    // Create HTTP server
    let config_data = web::Data::new(config.clone());
    let db_pool_data = web::Data::new(db_pool.clone());

    // Log upload configuration for debugging
    info!("Upload configuration:");
    info!(
        "  Directory: {} (absolute: {:?})",
        config.upload.dir,
        config.upload.get_absolute_upload_dir()
    );
    info!("  Max size: {} bytes", config.upload.max_size);
    info!(
        "  Image max dimensions: {}x{}",
        config.upload.image_max_width, config.upload.image_max_height
    );
    info!(
        "  Generate thumbnails: {}",
        config.upload.generate_thumbnails
    );
    info!("  Allowed types: {:?}", config.upload.allowed_types);
    info!(
        "  Current working directory: {:?}",
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("unknown"))
    );

    HttpServer::new(move || {
        App::new()
            .app_data(config_data.clone())
            .app_data(db_pool_data.clone())
            .app_data(geo_ip_data.clone())
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
