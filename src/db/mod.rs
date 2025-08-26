use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::RunQueryDsl;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::time::Duration;

use crate::config::DatabaseConfig;

pub mod models;
pub mod schemas;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

pub async fn establish_connection(
    config: &DatabaseConfig,
) -> Result<DbPool, Box<dyn std::error::Error + Send + Sync>> {
    let manager = ConnectionManager::<PgConnection>::new(&config.url);

    let pool = Pool::builder()
        .connection_customizer(Box::new(ConnectionCustomizer))
        .max_size(config.max_connections)
        .min_idle(Some(config.min_connections))
        .connection_timeout(Duration::from_secs(config.connect_timeout))
        .idle_timeout(Some(Duration::from_secs(config.idle_timeout)))
        .max_lifetime(Some(Duration::from_secs(config.max_lifetime)))
        .build(manager)?;

    // Test connection
    pool.get()?;

    // Run migrations
    run_migrations(&pool)?;

    Ok(pool)
}

fn run_migrations(pool: &DbPool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = pool.get()?;

    conn.run_pending_migrations(MIGRATIONS)?;

    Ok(())
}

#[derive(Debug)]
struct ConnectionCustomizer;

impl diesel::r2d2::CustomizeConnection<PgConnection, diesel::r2d2::Error> for ConnectionCustomizer {
    fn on_acquire(&self, conn: &mut PgConnection) -> Result<(), diesel::r2d2::Error> {
        // Set connection-specific settings
        diesel::sql_query("SET timezone = 'UTC'")
            .execute(conn)
            .map_err(|e| diesel::r2d2::Error::QueryError(e))?;

        diesel::sql_query("SET application_name = 'auth_service'")
            .execute(conn)
            .map_err(|e| diesel::r2d2::Error::QueryError(e))?;

        Ok(())
    }
}
