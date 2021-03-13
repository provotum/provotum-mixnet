use actix_web::{web, get, App, HttpResponse, HttpRequest, HttpServer, Responder};

async fn randomize(req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", &name)
}

#[get("/")]
async fn index(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("Hello from the index page!")
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