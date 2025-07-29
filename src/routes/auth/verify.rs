use actix_web::{HttpResponse, Responder, post};

#[post("/verify")]
async fn verify_user() -> impl Responder {
    HttpResponse::Ok().body("Verify endpoint")
}
