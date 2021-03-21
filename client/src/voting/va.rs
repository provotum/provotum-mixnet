use crate::voting::substrate::rpc::{create_vote, set_vote_phase, store_public_key};
use crypto::helper::Helper;
use crypto::{
    proofs::re_encryption::ReEncryptionProof,
    types::{Cipher, PublicKey},
};
use pallet_mixnet::types::{Topic, VotePhase};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use substrate_subxt::Client;
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};

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

pub async fn setup_vote(vote_title: String, topic_question: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

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

pub async fn change_vote_phase(vote: String, vote_phase: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create input parameters
    let vote_id = vote.as_bytes().to_vec();
    let vote_phase =
        VotePhase::from_str(&vote_phase).expect("only valid VotePhase values should be parsed!");

    // update vote phase to Voting
    set_vote_phase(&client, vote_id.clone(), vote_phase).await?;
    Ok(())
}
