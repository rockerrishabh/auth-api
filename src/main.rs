use std::env;

use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, http, web::Data};
use auth_api::{db, routes};
use dotenv::dotenv;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = db::establish_connection(database_url).await;

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("https://stellerseller.store")
            .allowed_origin_fn(|origin, _req_head| {
                origin.as_bytes().ends_with(b".stellerseller.store")
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(Data::new(db::AppState {
                db: db_pool.clone(),
            }))
            .service(hello)
            .configure(routes::config)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
