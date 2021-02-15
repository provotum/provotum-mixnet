mod calls;

use crate::calls::CreateVoteCall;
use crypto::helper::Helper;
use pallet_mixnet::types::{PublicParameters, Topic};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
use substrate_subxt::system::AccountStoreExt;
use substrate_subxt::{Call, ClientBuilder, Error, EventsDecoder, NodeTemplateRuntime, PairSigner};

impl Call<NodeTemplateRuntime> for CreateVoteCall {
    const MODULE: &'static str = "TemplateModule";
    const FUNCTION: &'static str = "create_vote";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {}
}

#[async_std::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let client = ClientBuilder::<NodeTemplateRuntime>::new()
        .set_url("ws://127.0.0.1:9944")
        .build()
        .await?;

    let block_number = 1;

    let block_hash = client.block_hash(Some(block_number.into())).await?;

    if let Some(hash) = block_hash {
        println!("Block hash for block number {}: {}", block_number, hash);
    } else {
        println!("Block number {} not found.", block_number);
    }

    let mut iter = client.account_iter(None).await?;
    while let Some((key, account)) = iter.next().await? {
        println!("{:?}: {:#?}", key, account.data.free);
    }

    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());

    // create the vote
    let (params, _, _) = Helper::setup_sm_system();
    let params: PublicParameters = params.into();
    let vote_id = "20201212".as_bytes().to_vec();
    let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

    let topic_id = "20201212-01".as_bytes().to_vec();
    let topic_question = "Moritz for President?".as_bytes().to_vec();
    let topic: Topic = (topic_id, topic_question);
    let topics = vec![topic];

    let response = client
        .watch(
            CreateVoteCall {
                params,
                title: vote_title,
                vote_id,
                topics,
            },
            &signer,
        )
        .await?;
    println!("response: {:?}", response);

    Ok(())
}
