use crate::voting::substrate::rpc::submit_ballot;
use crypto::{
    proofs::re_encryption::ReEncryptionProof,
    types::{Cipher, PublicKey},
};
use crypto::{random::Random, types::PublicKey as ElGamalPK};
use pallet_mixnet::types::Ballot;
use serde::{Deserialize, Serialize};
use sp_keyring::sr25519::sr25519::Pair;
use substrate_subxt::{sp_core::Pair as KeyPairGenerator, Client};
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime, PairSigner};
use surf::Body;

use super::substrate::rpc::get_vote_public_key;

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

async fn init() -> Result<Client<NodeTemplateRuntime>, Error> {
    env_logger::init();
    let url = "ws://127.0.0.1:9944";
    let client = ClientBuilder::<NodeTemplateRuntime>::new()
        .set_url(url)
        .build()
        .await?;
    Ok(client)
}

pub async fn create_votes(
    vote: String,
    question: String,
    nr_of_votes: usize,
    votes: Vec<u32>,
) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create the vote
    let vote_id = vote.as_bytes().to_vec();
    let topic_id = question.as_bytes().to_vec();
    let pk: ElGamalPK = get_vote_public_key(&client, vote_id.clone()).await?.into();
    let q = &pk.params.q();

    // generate random encryptions
    let encryptions = Random::generate_encryptions(&pk, q, nr_of_votes, votes);

    // submit some ballots
    for (index, cipher) in encryptions.into_iter().enumerate() {
        let index_string = (index as u64).to_string();
        let voter_keypair = KeyPairGenerator::from_string(&format!("//{}", index_string), None)?;
        let voter = PairSigner::<NodeTemplateRuntime, Pair>::new(voter_keypair);

        let body = RequestBody {
            pk: pk.clone(),
            cipher: cipher.clone(),
        };
        let response: ResponseBody = randomize_cipher(&body).await.unwrap();
        let proof_is_valid =
            ReEncryptionProof::verify(&pk, &response.proof, &cipher, &response.cipher);
        assert!(proof_is_valid);
        let re_encrypted_cipher = response.cipher;
        println!(
            "randomized ballot + verified proof for voter: {:?}",
            index_string
        );

        // create ballot
        let ballot: Ballot = Ballot {
            answers: vec![(topic_id.clone(), re_encrypted_cipher.into())],
        };

        // submit ballot
        let ballot_submission_hash =
            submit_ballot(&client, &voter, vote_id.clone(), ballot).await?;
        println!("ballot_submission_hash: {:?}", ballot_submission_hash);
    }
    Ok(())
}

pub async fn randomize_cipher(body: &RequestBody) -> Result<ResponseBody, surf::Error> {
    let body = Body::from_json(body)?;
    let response = surf::post("http://0.0.0.0:8080/randomize")
        .body(body)
        .recv_json::<ResponseBody>()
        .await?;
    Ok(response)
}
