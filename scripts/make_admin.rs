use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use std::env;

use auth_api::db::model::UserRole;
use auth_api::db::{model::User, schema::users, AppState};

fn main() {
    // Get database URL from environment
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Create connection pool
    let manager = ConnectionManager::<diesel::PgConnection>::new(database_url);
    let pool = Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    // Get email from command line args
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <user_email>", args[0]);
        std::process::exit(1);
    }
    let email = &args[1];

    // Get connection
    let mut conn = pool.get().expect("Failed to get connection");

    // Find user by email
    let user = users::table
        .filter(users::email.eq(email))
        .first::<User>(&mut conn)
        .optional()
        .expect("Failed to query user");

    match user {
        Some(user) => {
            // Update user role to admin
            let updated_user = diesel::update(users::table)
                .filter(users::id.eq(user.id))
                .set(users::role.eq(UserRole::Admin))
                .returning(User::as_returning())
                .get_result::<User>(&mut conn)
                .expect("Failed to update user");

            println!("Successfully made {} an admin!", updated_user.email);
        }
        None => {
            eprintln!("User with email {} not found", email);
            std::process::exit(1);
        }
    }
}
