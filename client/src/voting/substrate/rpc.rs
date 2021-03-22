use crate::voting::substrate::calls::{
    CastBallot, CombineDecryptedShares, CombinePublicKeyShares, CreateVote, SetVotePhase,
    StorePublicKey, StorePublicKeyShare, StoreQuestion, SubmitPartialDecryption,
};
use crate::voting::substrate::stores::{CiphersStore, PublicKeyStore, TallyStore};
use pallet_mixnet::types::{
    Ballot, Cipher, DecryptedShare, DecryptedShareProof, NrOfShuffles, PublicKey as SubstratePK,
    PublicKeyShare, PublicParameters, Title, Topic, TopicId, TopicResult, VoteId, VotePhase,
};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
use substrate_subxt::{system::System, Call, Client, ExtrinsicSuccess};
use substrate_subxt::{Error, NodeTemplateRuntime, PairSigner};

pub async fn get_ciphers(
    client: &Client<NodeTemplateRuntime>,
    topic_id: TopicId,
    nr_of_shuffles: NrOfShuffles,
) -> Result<Vec<Cipher>, Error> {
    let store = CiphersStore {
        topic_id,
        nr_of_shuffles,
    };
    let ciphers_as_bytes = client
        .fetch(&store, None)
        .await?
        .ok_or("failed to fetch ciphers!")?;
    Ok(ciphers_as_bytes)
}

pub async fn get_vote_public_key(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
) -> Result<SubstratePK, Error> {
    let store = PublicKeyStore { vote_id };
    let pk = client
        .fetch(&store, None)
        .await?
        .ok_or("failed to fetch public key!")?;
    Ok(pk)
}
pub async fn get_tally(
    client: &Client<NodeTemplateRuntime>,
    topic_id: TopicId,
) -> Result<TopicResult, Error> {
    let store = TallyStore { topic_id };
    let tally = client
        .fetch(&store, None)
        .await?
        .ok_or("failed to fetch tally!")?;
    Ok(tally)
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

pub async fn store_question(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    topic: Topic,
    batch_size: u64,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = StoreQuestion {
        vote_id,
        topic,
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

pub async fn store_public_key(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    pk: SubstratePK,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = StorePublicKey { vote_id, pk };
    return watch(&signer, client, call).await;
}

pub async fn store_public_key_share(
    client: &Client<NodeTemplateRuntime>,
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    vote_id: VoteId,
    pk_share: PublicKeyShare,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let call = StorePublicKeyShare { vote_id, pk_share };
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

pub async fn combine_pk_shares(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = CombinePublicKeyShares { vote_id };
    return watch(&signer, client, call).await;
}

pub async fn combine_decrypted_shares(
    client: &Client<NodeTemplateRuntime>,
    vote_id: VoteId,
    topic_id: TopicId,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(AccountKeyring::Alice.pair());
    let call = CombineDecryptedShares {
        vote_id,
        topic_id,
        encoded: false,
        nr_of_shuffles: 3,
    };
    return watch(&signer, client, call).await;
}

pub async fn submit_partial_decryptions(
    client: &Client<NodeTemplateRuntime>,
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    vote_id: VoteId,
    topic_id: TopicId,
    shares: Vec<DecryptedShare>,
    proof: DecryptedShareProof,
    nr_of_shuffles: NrOfShuffles,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let call = SubmitPartialDecryption {
        vote_id,
        topic_id,
        shares,
        proof,
        nr_of_shuffles,
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
