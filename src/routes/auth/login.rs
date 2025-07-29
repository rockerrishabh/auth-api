use actix_web::{HttpResponse, Responder, post};

#[post("/login")]
async fn login_user() -> impl Responder {
    HttpResponse::Ok().body("Login endpoint")
}
