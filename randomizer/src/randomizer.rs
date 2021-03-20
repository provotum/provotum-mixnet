use actix_web::{post, web, Responder};
use crypto::{
    encryption::ElGamal,
    random::Random,
    types::{Cipher, PublicKey},
};
use serde::{Deserialize, Serialize};

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
    // get a new random number
    let r = Random::get_random_less_than(&body.pk.params.q());

    // re-encrypt the cipher using the provided public key
    let cipher = ElGamal::re_encrypt(&body.cipher, &r, &body.pk);

    // return the re-encrypted cipher
    web::Json(ResponseBody { cipher })
}

#[cfg(test)]
mod tests {
    use super::{randomize_ballot, RequestBody, ResponseBody};
    use actix_web::{test, App};
    use crypto::{encryption::ElGamal, helper::Helper, random::Random};
    use num_bigint::BigUint;
    use num_traits::One;

    #[actix_rt::test]
    async fn test_get_randomize_ballot() {
        let app = App::new().service(randomize_ballot);
        let mut test_app = test::init_service(app).await;
        let req = test::TestRequest::get().uri("/randomize").to_request();
        let resp = test::call_service(&mut test_app, req).await;
        assert!(resp.status().is_client_error());
    }

    #[actix_rt::test]
    async fn test_post_randomize_ballot() {
        let app = App::new().service(randomize_ballot);
        let mut test_app = test::init_service(app).await;

        let (_, sk, pk) = Helper::setup_tiny_system();
        let q = &pk.params.q();
        let vote = &BigUint::one();
        let r = Random::get_random_less_than(q);
        let cipher = ElGamal::encrypt(vote, &r, &pk);
        let request_body = RequestBody {
            pk,
            cipher: cipher.clone(),
        };

        // send post request to re-encrypt ballot
        let req = test::TestRequest::post()
            .uri("/randomize")
            .set_json(&request_body)
            .to_request();

        // read response
        let resp: ResponseBody = test::read_response_json(&mut test_app, req).await;

        // ensure that the encrypted vote and re-encrypted vote are not the same
        assert_ne!(&resp.cipher, &cipher);

        // ensure that the decrypted re-encrypted vote is still 1
        let decrypted = ElGamal::decrypt(&resp.cipher, &sk);
        assert_eq!(&decrypted, vote);
    }
}
