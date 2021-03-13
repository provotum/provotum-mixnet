use actix_web::{HttpRequest, Responder};
use serde::{Serialize, Deserialize};

pub async fn randomize(req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", &name)
}