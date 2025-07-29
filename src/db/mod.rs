use diesel::{
    PgConnection,
    r2d2::{ConnectionManager, Pool},
};

pub mod model;
pub mod schema;

pub type DbConnection = Pool<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct AppState {
    pub db: DbConnection,
}

pub async fn establish_connection(database_url: String) -> DbConnection {
    let manager = ConnectionManager::<PgConnection>::new(database_url);

    Pool::builder()
        .max_size(15)
        .build(manager)
        .expect("Could not build connection pool")
}
