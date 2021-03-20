use actix_web::{post, web, Responder};
use crypto::{
    encryption::ElGamal,
    proofs::re_encryption::ReEncryptionProof,
    random::Random,
    types::{Cipher, PublicKey},
};
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct RequestBody {
    pub pk: PublicKey,
    pub cipher: Cipher,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct ResponseBody {
    pub proof: ReEncryptionProof,
    pub cipher: Cipher,
}

#[post("/randomize")]
pub async fn randomize_ballot(body: web::Json<RequestBody>) -> impl Responder {
    // common values
    let cipher = body.cipher.clone();
    let pk = body.pk.clone();
    let q = &pk.params.q();

    // 1. re-encrypt the cipher
    let r1 = Random::get_random_less_than(q);
    let re_encrypted_cipher = ElGamal::re_encrypt(&cipher, &r1, &pk);

    // 2. generate a proof to show that the re-encryption is valid/not something else
    // 2.1 generate c_one -> the encryption of 1 using the re-encryption random r1
    let one = BigUint::one();
    let c_one = ElGamal::encrypt(&one, &r1, &pk);

    // 2.2 generate the proof
    let r2 = Random::get_random_less_than(q);
    let h2 = Random::get_random_less_than(q);
    let s2 = Random::get_random_less_than(q);
    let proof = ReEncryptionProof::generate(&r1, &r2, &h2, &s2, &c_one, &pk);

    // return the re-encrypted cipher
    web::Json(ResponseBody {
        cipher: re_encrypted_cipher,
        proof,
    })
}

#[cfg(test)]
mod tests {
    use super::{randomize_ballot, RequestBody, ResponseBody};
    use actix_web::{test, App};
    use crypto::{
        encryption::ElGamal, helper::Helper, proofs::re_encryption::ReEncryptionProof,
        random::Random,
    };
    use num_bigint::BigUint;

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

        let (_, sk, pk) = Helper::setup_sm_system();
        let q = &pk.params.q();
        let vote = &BigUint::from(13u32);
        let r = Random::get_random_less_than(q);
        let cipher = ElGamal::encrypt(vote, &r, &pk);
        let request_body = RequestBody {
            pk: pk.clone(),
            cipher: cipher.clone(),
        };

        // send post request to re-encrypt ballot
        let req = test::TestRequest::post()
            .uri("/randomize")
            .set_json(&request_body)
            .to_request();

        // read response
        let resp: ResponseBody = test::read_response_json(&mut test_app, req).await;
        let re_encrypted_cipher = resp.cipher;

        // ensure that the encrypted vote and re-encrypted vote are not the same
        assert_ne!(&re_encrypted_cipher, &cipher);

        // verify the re-encryption proof
        let proof_is_valid =
            ReEncryptionProof::verify(&pk, &resp.proof, &cipher, &re_encrypted_cipher);
        assert!(proof_is_valid);

        // ensure that the decrypted re-encrypted vote is still 13
        let decrypted = ElGamal::decrypt(&re_encrypted_cipher, &sk);
        assert_eq!(&decrypted, vote);
    }
}
