pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod services;

pub use config::AppConfig;
pub use db::DbPool;
pub use error::{AuthError, AuthResult};
pub use middleware::extract_user_id_from_request;
pub use routes::configure_routes_simple;
