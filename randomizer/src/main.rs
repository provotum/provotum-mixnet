mod randomize;

use actix_web::{web, get, App, HttpResponse, HttpRequest, HttpServer, Responder};
use crate::randomize::randomize;

#[get("/")]
async fn index(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("hi there!")
}

#[get("/health")]
async fn health(_req: HttpRequest) -> impl Responder {
    HttpResponse::NoContent()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(health)
            .route("/{name}", web::get().to(randomize))
    })
    .bind(("0.0.0.0", 8080))?
    .run().await
}