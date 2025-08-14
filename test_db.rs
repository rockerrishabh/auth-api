use diesel::prelude::*;
use diesel::pg::PgConnection;
use std::env;

fn main() {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let mut conn = PgConnection::establish(&database_url)
        .expect("Error connecting to database");

    // Test if tables exist
    let result: Result<Vec<String>, diesel::result::Error> = diesel::sql_query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
    )
    .load(&mut conn);

    match result {
        Ok(tables) => {
            println!("Tables in database:");
            for table in tables {
                println!("- {}", table);
            }
        }
        Err(e) => {
            println!("Error querying tables: {}", e);
        }
    }
}