use actix_cors::Cors;
use actix_web::{
    App, HttpResponse, HttpServer, Responder, get, http::header, middleware::Logger, web::Data,
};
use auth_api::{
    config::AppConfig,
    db::{self, AppState},
    mail::EmailService,
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
    env_logger::init();

    // Load configuration from environment
    let config: AppConfig =
        AppConfig::from_env().expect("Failed to load configuration from environment variables");

    // Initialize database
    let db_pool = db::establish_connection(config.database_url.clone()).await;

    // Initialize email service
    let email_service =
        EmailService::new(config.email.clone()).expect("Failed to initialize email service");

    // Setup thread pool
    let cpus = num_cpus::get();
    rayon::ThreadPoolBuilder::new()
        .num_threads(cpus)
        .build_global()
        .expect("Failed to build Rayon global thread pool");

    // Ensure upload directory exists
    std::fs::create_dir_all(&config.upload.upload_dir).expect("Failed to create upload directory");

    let server_config = config.server.clone();
    let frontend_url = config.server.frontend_url.clone();

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&frontend_url)
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:5173") // Vite dev server
            .allowed_origin("http://localhost:4173") // Vite preview server
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT, header::CONTENT_TYPE])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(Data::new(AppState {
                db: db_pool.clone(),
            }))
            .app_data(Data::new(config.clone()))
            .app_data(Data::new(email_service.clone()))
            .service(
                actix_files::Files::new("/static", "static")
                    .show_files_listing()
                    .use_last_modified(true),
            )
            .service(hello)
            .configure(routes::config)
    })
    .bind((server_config.host.as_str(), server_config.port))?
    .run()
    .await
}
