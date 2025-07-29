use actix_web::{HttpResponse, Responder, get};

#[get("/refresh")]
async fn refresh_token() -> impl Responder {
    HttpResponse::Ok().body("Refresh Token endpoint")
}
