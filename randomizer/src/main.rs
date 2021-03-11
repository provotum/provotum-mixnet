use actix_web::{web, get, App, HttpResponse, HttpRequest, HttpServer, Responder};

async fn randomize(req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", &name)
}

#[get("/")]
async fn index(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("Hello from the index page!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(index)
            .route("/{name}", web::get().to(randomize))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}