use crate::voting::substrate::rpc::{
    combine_decrypted_shares, combine_pk_shares, create_vote, get_tally, set_vote_phase,
    store_question,
};
use crypto::helper::Helper;
use pallet_mixnet::types::{Topic, VotePhase};
use std::str::FromStr;
use substrate_subxt::Client;
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};

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
    let (params, _, _) = Helper::setup_lg_system();
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
        75,
    )
    .await?;
    println!(
        "create_vote_response: {:?}",
        create_vote_response.events[0].variant
    );
    // // DON'T USE THIS IN PRODUCTION ONLY FOR DEV PURPOSES
    // // setup the public key
    // let public_key_response = store_public_key(&client, vote_id.clone(), pk.clone().into()).await?;
    // println!(
    //     "public_key_response: {:?}",
    //     public_key_response.events[0].variant
    // );
    Ok(())
}

pub async fn setup_question(vote: String, question: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create the question + input parameters
    let vote_id = vote.as_bytes().to_vec();
    let topic_id = question.as_bytes().to_vec();
    let topic_question = question.as_bytes().to_vec();
    let topic: Topic = (topic_id.clone(), topic_question);

    // store question
    let response = store_question(&client, vote_id, topic, 75).await?;
    println!("response: {:?}", response.events[0].variant);
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
    let response = set_vote_phase(&client, vote_id.clone(), vote_phase).await?;
    println!("response: {:?}", response.events[0].variant);
    Ok(())
}

pub async fn combine_public_key_shares(vote: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create input parameters
    let vote_id = vote.as_bytes().to_vec();

    // update vote phase to Voting
    let response = combine_pk_shares(&client, vote_id.clone()).await?;
    println!("response: {:?}", response.events[0].variant);
    Ok(())
}

pub async fn tally_question(vote: String, question: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create input parameters
    let vote_id = vote.as_bytes().to_vec();
    let topic_id = question.as_bytes().to_vec();

    // update vote phase to Voting
    let response = combine_decrypted_shares(&client, vote_id, topic_id).await?;
    println!(
        "response: {:?}, data: {:?}",
        response.events[0].variant, response.events[0]
    );
    Ok(())
}

pub async fn get_result(question: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create input parameters
    let topic_id = question.as_bytes().to_vec();

    // update vote phase to Voting
    let result = get_tally(&client, topic_id).await?;
    println!("The result of the question: {:?} is...", question);
    for (vote, count) in result {
        println!("\tVote: {:?}, Count: {:?}", vote, count);
    }
    Ok(())
}
