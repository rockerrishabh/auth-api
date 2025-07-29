use actix_web::{HttpResponse, Responder, get};

#[get("/me")]
async fn user() -> impl Responder {
    HttpResponse::Ok().body("Me endpoint")
}
