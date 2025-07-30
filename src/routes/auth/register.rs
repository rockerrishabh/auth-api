use actix_web::{
    HttpResponse, Responder, post,
    web::{Data, Json},
};
use diesel::{
    ExpressionMethods, RunQueryDsl, SelectableHelper,
    query_dsl::methods::{FilterDsl, SelectDsl},
};

use crate::db::{
    AppState,
    model::{NewUser, User},
    schema::users,
};

#[derive(serde::Deserialize, Debug)]
struct RegisterData {
    name: String,
    email: String,
    password: String,
}

#[post("/register")]
async fn register_user(data: Json<RegisterData>, pool: Data<AppState>) -> impl Responder {
    let user_data = data.into_inner();

    match pool.db.get() {
        Ok(mut conn) => {
            let results = users::table
                .filter(users::dsl::email.eq(user_data.email.clone()))
                .select(User::as_select())
                .load::<User>(&mut conn)
                .expect("Error loading user");

            if !results.is_empty() {
                return HttpResponse::Conflict().body("Email already exists");
            }

            let new_user = NewUser {
                name: &user_data.name,
                email: &user_data.email,
                password_hash: Some(&user_data.password),
            };

            let user = diesel::insert_into(users::table)
                .values(&new_user)
                .returning(User::as_returning())
                .get_result::<User>(&mut conn)
                .expect("Error saving new user");

            println!("New user created: {:?}", user);

            HttpResponse::Created().body("User registered successfully")
        }
        Err(e) => {
            eprintln!("Database connection error: {}", e);
            HttpResponse::InternalServerError().body("Failed to connect to the database")
        }
    }
}
