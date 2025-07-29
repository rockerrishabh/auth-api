use actix_web::{HttpResponse, Responder, post};

#[post("/register")]
async fn register_user() -> impl Responder {
    HttpResponse::Ok().body("Register endpoint")
}
