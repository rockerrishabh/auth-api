use actix_web::{HttpResponse, Responder, delete};

#[delete("/logout")]
async fn logout_user() -> impl Responder {
    HttpResponse::Ok().body("Logout endpoint")
}
