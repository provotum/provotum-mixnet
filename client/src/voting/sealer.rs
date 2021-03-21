use crate::voting::substrate::rpc::{
    create_vote, get_ciphers, get_vote_ids, set_vote_phase, store_public_key, submit_ballot,
};
use crypto::{helper::Helper, random::Random};
use crypto::{
    proofs::re_encryption::ReEncryptionProof,
    types::{Cipher, PublicKey},
};
use pallet_mixnet::types::{Ballot, Topic, VotePhase};
use serde::{Deserialize, Serialize};
use sp_keyring::sr25519::sr25519::Pair;
use std::{thread, time};
use substrate_subxt::sp_core::Pair as KeyPairGenerator;
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime, PairSigner};
use surf::Body;

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

pub async fn setup_vote(vote_title: String, topic_question: String) -> Result<(), Error> {
    env_logger::init();
    let voting_authority_url = "ws://127.0.0.1:9944";
    let client = ClientBuilder::<NodeTemplateRuntime>::new()
        .set_url(voting_authority_url)
        .build()
        .await?;

    // create the vote
    let (params, _, pk) = Helper::setup_lg_system();
    let vote_id = vote_title.as_bytes().to_vec();
    let vote_title = vote_title.as_bytes().to_vec();

    // create the question
    let topic_id = topic_question.as_bytes().to_vec();
    let topic_question = topic_question.as_bytes().to_vec();
    let topic: Topic = (topic_id.clone(), topic_question);
    let topics = vec![topic];

    // setup the vote
    let create_vote_response = create_vote(
        &client,
        params.into(),
        vote_title,
        vote_id.clone(),
        topics,
        100,
    )
    .await?;
    println!(
        "create_vote_response: {:?}",
        create_vote_response.events[0].variant
    );
    // setup the public key
    let public_key_response = store_public_key(&client, vote_id.clone(), pk.clone().into()).await?;
    println!(
        "public_key_response: {:?}",
        public_key_response.events[0].variant
    );
    Ok(())
}

pub async fn test() -> Result<(), Error> {
    env_logger::init();

    let voting_authority_url = "ws://127.0.0.1:9944";
    let client = ClientBuilder::<NodeTemplateRuntime>::new()
        .set_url(voting_authority_url)
        .build()
        .await?;

    // create the vote
    let (params, _, pk) = Helper::setup_sm_system();
    let q = &params.q();
    let vote_id = "2020-12-12".as_bytes().to_vec();
    let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

    let topic_id = "2020-12-12-vote01".as_bytes().to_vec();
    let topic_question = "Moritz for President?".as_bytes().to_vec();
    let topic: Topic = (topic_id.clone(), topic_question);
    let topics = vec![topic];

    // create vote
    let create_vote_response = create_vote(
        &client,
        params.into(),
        vote_title,
        vote_id.clone(),
        topics,
        100,
    )
    .await?;
    println!(
        "create_vote_response: {:?}",
        create_vote_response.events[0].variant
    );

    // setup the public key
    let public_key_response = store_public_key(&client, vote_id.clone(), pk.clone().into()).await?;
    println!(
        "public_key_response: {:?}",
        public_key_response.events[0].variant
    );

    // update vote phase to Voting
    let vote_phase_voting = set_vote_phase(&client, vote_id.clone(), VotePhase::Voting).await?;
    println!(
        "vote_phase_voting: {:?}",
        vote_phase_voting.events[0].variant
    );

    // fetch all exisiting vote ids
    get_vote_ids(&client).await?;

    // TODO: If possible make the number of moves configurable
    let encryptions = Random::generate_random_encryptions(&pk, q, 500);

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

    // wait until the end of the block
    thread::sleep(time::Duration::from_secs(6));

    // fetch all existing ciphers
    get_ciphers(&client, topic_id.clone(), 0).await?;

    // update vote phase to Tallying
    let vote_phase_tally = set_vote_phase(&client, vote_id, VotePhase::Tallying).await?;
    println!("vote_phase_tally: {:?}", vote_phase_tally.events[0].variant);

    // wait for the shuffle to be performed and submitted
    let timeout = time::Duration::from_secs(20);
    thread::sleep(timeout);

    // fetch all new ciphers (after the shuffle)
    get_ciphers(&client, topic_id, 1).await?;

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
