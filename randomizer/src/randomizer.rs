use crate::helper::get_random_less_than;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use crypto::{
    encryption::ElGamal,
    types::{Cipher, PublicKey},
};
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

#[get("/{name}")]
pub async fn random_hello_world(req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", &name)
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct RequestBody {
    pub pk: PublicKey,
    pub cipher: Cipher,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct ResponseBody {
    // pub proof: ReEncryptionProof,
    pub cipher: Cipher,
}

#[post("/randomize")]
pub async fn randomize_ballot(body: web::Json<RequestBody>) -> impl Responder {
    println!("pk: {:?}", body.pk);
    println!("cipher: {:?}", body.cipher);
    let q = &body.pk.params.q();
    let r = get_random_less_than(q);
    let cipher = ElGamal::encrypt(&BigUint::one(), &r, &body.pk);
    HttpResponse::Ok().json(cipher)
}
