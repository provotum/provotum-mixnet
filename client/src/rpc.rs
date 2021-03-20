use crate::calls::{CastBallot, CreateVote, SetVotePhase, StorePublicKey};
use crate::stores::{CiphersStore, VotesStore};
use pallet_mixnet::types::{
    Ballot, NrOfShuffles, PublicKey as SubstratePK, PublicParameters, Title, Topic, TopicId,
    VoteId, VotePhase,
};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
use substrate_subxt::{system::System, Call, Client, ExtrinsicSuccess};
use substrate_subxt::{Error, NodeTemplateRuntime, PairSigner};

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
    batch_size: u64,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = CreateVote {
        params,
        title,
        vote_id,
        topics,
        batch_size,
    };
    return watch(&signer, client, call).await;
}

pub async fn submit_ballot(
    client: &Client<NodeTemplateRuntime>,
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    vote_id: VoteId,
    ballot: Ballot,
) -> Result<<NodeTemplateRuntime as System>::Hash, Error> {
    let call = CastBallot { vote_id, ballot };
    return submit(signer, client, call).await;
}

pub async fn watch_ballot(
    client: &Client<NodeTemplateRuntime>,
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    vote_id: VoteId,
    ballot: Ballot,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let call = CastBallot { vote_id, ballot };
    return watch(signer, client, call).await;
}

pub async fn store_public_key(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    pk: SubstratePK,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = StorePublicKey { vote_id, pk };
    return watch(&signer, client, call).await;
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
    return watch(&signer, client, call).await;
}

async fn watch<C: Call<NodeTemplateRuntime> + Send + Sync>(
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    client: &Client<NodeTemplateRuntime>,
    call: C,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    return client.watch(call, signer).await;
}

async fn submit<C: Call<NodeTemplateRuntime> + Send + Sync>(
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    client: &Client<NodeTemplateRuntime>,
    call: C,
) -> Result<<NodeTemplateRuntime as System>::Hash, Error> {
    return client.submit(call, signer).await;
}
