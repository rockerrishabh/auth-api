use std::env;

use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, http::header, web::Data};
use auth_api::{
    db::{self, AppState},
    mail::EmailConfig,
    routes,
};
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
    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER must be set");
    let smtp_port: u16 = env::var("SMTP_PORT")
        .expect("SMTP_PORT must be set")
        .parse()
        .expect("SMTP_PORT must be a valid number");
    let smtp_user = env::var("SMTP_USER").expect("SMTP_USER must be set");
    let smtp_user_name = env::var("SMTP_USER_NAME").expect("SMTP_USER_NAME must be set");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("https://stellerseller.store")
            .allowed_origin_fn(|origin, _req_head| {
                origin.as_bytes().ends_with(b".stellerseller.store")
            })
            .allowed_origin("http://localhost")
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
            .allowed_header(header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(Data::new(AppState {
                db: db_pool.clone(),
            }))
            .app_data(Data::new(EmailConfig {
                smtp_server: smtp_server.clone(),
                smtp_port,
                smtp_user: smtp_user.clone(),
                smtp_user_name: smtp_user_name.clone(),
                smtp_password: smtp_password.clone(),
            }))
            .service(
                actix_files::Files::new("/static", "./static/.")
                    .show_files_listing()
                    .use_last_modified(true),
            )
            .service(hello)
            .configure(routes::config)
    })
    .bind(("0.0.0.0", 5000))?
    .run()
    .await
}
