use actix_web::{
    HttpResponse, Responder, post,
    web::{Data, Json},
};
use diesel::{
    ExpressionMethods, RunQueryDsl, SelectableHelper,
    query_dsl::methods::{FilterDsl, SelectDsl},
};

use crate::{
    db::{
        AppState,
        model::{NewUser, User},
        schema::users,
    },
    mail::{EmailConfig, send_email, templates::verification::verification_email},
};

#[derive(serde::Deserialize, Debug)]
struct RegisterData {
    name: String,
    email: String,
    password: String,
}

#[post("/register")]
async fn register_user(
    data: Json<RegisterData>,
    pool: Data<AppState>,
    config: Data<EmailConfig>,
) -> impl Responder {
    let user_data = data.into_inner();

    match pool.db.get() {
        Ok(mut conn) => {
            let results = users::table
                .filter(users::dsl::email.eq(user_data.email.clone()))
                .select(User::as_select())
                .load::<User>(&mut conn)
                .expect("Error loading user");

            if !results.is_empty() {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "message": "User with this email already exists"
                }));
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

            let token = uuid::Uuid::new_v4().to_string();

            let mail = verification_email(&user.name, &user.email, token);

            let mail_result = send_email(mail, config.as_ref());

            if let Err(e) = mail_result {
                eprintln!("Failed to send verification email: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "message": "Failed to send verification email"
                }));
            }

            HttpResponse::Created().json(serde_json::json!({
                "message": "User registered successfully",
                "user": {
                    "id": user.id,
                    "name": user.name,
                    "email": user.email,
                }
            }))
        }
        Err(e) => {
            eprintln!("Database connection error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Database connection error"
            }))
        }
    }
}
