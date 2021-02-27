mod calls;
mod random;
mod stores;

use crate::calls::{CreateVote, SetVotePhase, StorePublicKey};
use crate::stores::{CiphersStore, VotesStore};
use calls::CastBallot;
use crypto::helper::Helper;
use pallet_mixnet::types::{
    Ballot, NrOfShuffles, PublicKey as SubstratePK, PublicParameters, Title, Topic, TopicId,
    VoteId, VotePhase,
};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
use std::{thread, time};
use substrate_subxt::{Call, Client, ExtrinsicSuccess};
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime, PairSigner};

#[async_std::main]
async fn main() -> Result<(), Error> {
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
    let create_vote_response =
        create_vote(&client, params.into(), vote_title, vote_id.clone(), topics).await?;
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
    let encryptions = random::Random::get_random_encryptions(&pk, q, 6, false);

    // submit some ballots
    for cipher in encryptions.into_iter() {
        // create ballot
        let ballot: Ballot = Ballot {
            answers: vec![(topic_id.clone(), cipher.into())],
        };

        // submit ballot
        let cast_ballot_response = cast_ballot(&client, vote_id.clone(), ballot).await?;
        println!(
            "cast_ballot_response: {:?}",
            cast_ballot_response.events[0].variant
        );
    }

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

pub async fn get_vote_ids(client: &Client<NodeTemplateRuntime>) -> Result<Vec<String>, Error> {
    let store = VotesStore {};
    let vote_ids_as_bytes = client
        .fetch(&store, None)
        .await?
        .ok_or("failed to fetch vote_ids!")?;
    let vote_ids = vote_ids_as_bytes
        .iter()
        .map(|v| {
            std::str::from_utf8(v)
                .expect("cannot convert &[u8] to str")
                .to_owned()
        })
        .collect::<Vec<String>>();
    println!("vote_ids: {:?}", vote_ids);
    Ok(vote_ids)
}

pub async fn get_ciphers(
    client: &Client<NodeTemplateRuntime>,
    topic_id: TopicId,
    nr_of_shuffles: NrOfShuffles,
) -> Result<(), Error> {
    let store = CiphersStore {
        topic_id,
        nr_of_shuffles,
    };
    let ciphers_as_bytes = client
        .fetch(&store, None)
        .await?
        .ok_or("failed to fetch ciphers!")?;
    println!("# of ciphers: {:?}", ciphers_as_bytes.len());
    Ok(())
}

pub async fn create_vote(
    client: &Client<NodeTemplateRuntime>,
    params: PublicParameters,
    title: Title,
    vote_id: VoteId,
    topics: Vec<Topic>,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = CreateVote {
        params,
        title,
        vote_id,
        topics,
    };
    return submit(&signer, client, call).await;
}

pub async fn cast_ballot(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    ballot: Ballot,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = CastBallot { vote_id, ballot };
    return submit(&signer, client, call).await;
}

pub async fn store_public_key(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    pk: SubstratePK,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = StorePublicKey { vote_id, pk };
    return submit(&signer, client, call).await;
}

pub async fn set_vote_phase(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    vote_phase: VotePhase,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = SetVotePhase {
        vote_id,
        vote_phase,
    };
    return submit(&signer, client, call).await;
}

async fn submit<C: Call<NodeTemplateRuntime> + Send + Sync>(
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    client: &Client<NodeTemplateRuntime>,
    call: C,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    return client.watch(call, signer).await;
}
