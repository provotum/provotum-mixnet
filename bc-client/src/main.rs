mod calls;
mod stores;

use crate::calls::{CreateVote, SetVotePhase};
use crate::stores::{CiphersStore, VotesStore};
use calls::CastBallot;
use crypto::{encryption::ElGamal, helper::Helper, types::Cipher as BigCipher};
use num_bigint::BigUint;
use num_traits::One;
use pallet_mixnet::types::{
    Ballot, Cipher, NrOfShuffles, PublicParameters, Title, Topic, TopicId, VoteId, VotePhase,
};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
use std::str::from_utf8;
use substrate_subxt::{system::AccountStoreExt, Call, Client, ExtrinsicSuccess};
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
    let (params, sk, pk) = Helper::setup_sm_system();
    let q = &params.q();
    let vote_id = "20201212".as_bytes().to_vec();
    let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

    let topic_id = "20201212-01".as_bytes().to_vec();
    let topic_question = "Moritz for President?".as_bytes().to_vec();
    let topic: Topic = (topic_id.clone(), topic_question);
    let topics = vec![topic];

    // let block_number = 1;
    // let block_hash_response = get_block_hash(&client, block_number).await;

    let create_vote_response =
        create_vote(&client, params.into(), vote_title, vote_id.clone(), topics).await;
    println!("create_vote_response: {:?}", create_vote_response);

    // update vote phase to Voting
    let set_vote_phase_response = set_vote_phase(&client, vote_id.clone(), VotePhase::Voting).await;
    println!("set_vote_phase_response: {:?}", set_vote_phase_response);

    // fetch all exisiting vote ids
    let vote_ids = get_vote_ids(&client).await?;

    // fetch all existing ciphers
    let ciphers = get_ciphers(&client, topic_id.clone(), 0).await?;

    // submit some ballots
    // create cipher
    let message = BigUint::from(3u32);
    let random = BigUint::from(1u32);
    let cipher: BigCipher = ElGamal::encrypt(&message, &random, &pk);
    let cipher_as_bytes: Cipher = cipher.into();
    let ballot: Ballot = Ballot {
        answers: vec![(topic_id.clone(), cipher_as_bytes)],
    };

    // submit ballot
    let cast_ballot_response = cast_ballot(&client, vote_id, ballot).await;
    println!("cast_ballot_response: {:?}", cast_ballot_response);

    // fetch all existing ciphers
    let ciphers = get_ciphers(&client, topic_id, 0).await?;

    // TODO: update vote phase to Tallying

    Ok(())
}

pub async fn get_block_hash(
    client: &Client<NodeTemplateRuntime>,
    block_number: u32,
) -> Result<(), Error> {
    let block_hash = client.block_hash(Some(block_number.into())).await?;

    if let Some(hash) = block_hash {
        println!("Block hash for block number {}: {}", block_number, hash);
    } else {
        println!("Block number {} not found.", block_number);
    }

    let mut iter = client.account_iter(None).await?;
    while let Some((key, account)) = iter.next().await? {
        println!("{:?}: {:#?}", key, account);
    }
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
    let create_vote_call = CreateVote {
        params,
        title,
        vote_id,
        topics,
    };
    return submit(&signer, client, create_vote_call).await;
}

pub async fn get_vote_ids(client: &Client<NodeTemplateRuntime>) -> Result<Vec<String>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let store = VotesStore {};
    let mut vote_ids_as_bytes = client
        .fetch(&store, None)
        .await?
        .ok_or_else(|| "failed to fetch vote_ids!")?;
    let vote_ids = vote_ids_as_bytes
        .iter()
        .map(|v| {
            std::str::from_utf8(v)
                .expect("cannot convert &[u8] to str")
                .to_owned()
        })
        .collect::<Vec<String>>();
    println!("vote_ids: {:#?}", vote_ids);
    Ok(vote_ids.clone())
}

pub async fn get_ciphers(
    client: &Client<NodeTemplateRuntime>,
    topic_id: TopicId,
    nr_of_shuffles: NrOfShuffles,
) -> Result<Vec<Vec<u8>>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let store = CiphersStore {
        topic_id,
        nr_of_shuffles,
    };
    let mut ciphers_as_bytes = client.fetch(&store, None).await?;

    // .ok_or_else(|| "failed to fetch ciphers!")?;
    println!("ciphers_as_bytes: {:#?}", ciphers_as_bytes);
    // let ciphers = ciphers_as_bytes
    //     .iter()
    //     .map(|v| std::str::from_utf8(v).expect("cannot convert &[u8] to str"))
    //     .collect::<Vec<&str>>();
    // println!("ciphers: {:#?}", ciphers);
    Ok(Vec::new())
}

pub async fn cast_ballot(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    ballot: Ballot,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let cast_ballot = CastBallot { vote_id, ballot };
    return submit(&signer, client, cast_ballot).await;
}

pub async fn set_vote_phase(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    vote_phase: VotePhase,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let set_vote_phase = SetVotePhase {
        vote_id,
        vote_phase,
    };
    return submit(&signer, client, set_vote_phase).await;
}

async fn submit<C: Call<NodeTemplateRuntime> + Send + Sync>(
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    client: &Client<NodeTemplateRuntime>,
    call: C,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    return client.watch(call, signer).await;
}
