mod health;
mod helper;
mod index;
mod randomizer;

use actix_web::{App, HttpServer};
use health::get_health;
use index::get_index;
use randomizer::randomize_ballot;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(get_index)
            .service(get_health)
            .service(randomize_ballot)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
