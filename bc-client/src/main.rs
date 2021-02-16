mod calls;

use crate::calls::{CreateVote, SetVotePhase};
use crypto::helper::Helper;
use pallet_mixnet::types::{PublicParameters, Topic, VoteId, VotePhase};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
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

    // let block_number = 1;
    // let block_hash_response = get_block_hash(&client, block_number).await;

    let create_vote_response = create_vote(&client).await;
    println!("create_vote_response: {:?}", create_vote_response);

    // TODO: update vote phase to Voting
    let vote_id = "20201212".as_bytes().to_vec();
    let set_vote_phase_response = set_vote_phase(&client, vote_id, VotePhase::Voting).await;
    println!("set_vote_phase_response: {:?}", set_vote_phase_response);

    // TODO: submit some ballots

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
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    // create the vote
    let (params, _, _) = Helper::setup_sm_system();
    let params: PublicParameters = params.into();
    let vote_id = "20201212".as_bytes().to_vec();
    let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

    let topic_id = "20201212-01".as_bytes().to_vec();
    let topic_question = "Moritz for President?".as_bytes().to_vec();
    let topic: Topic = (topic_id, topic_question);
    let topics = vec![topic];

    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let create_vote_call = CreateVote {
        params,
        title: vote_title,
        vote_id,
        topics,
    };
    return submit(&signer, client, create_vote_call).await;
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
