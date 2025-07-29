use actix_web::{HttpResponse, Responder, post};

#[post("/reset-password")]
async fn reset_password() -> impl Responder {
    HttpResponse::Ok().body("Reset Password endpoint")
}
