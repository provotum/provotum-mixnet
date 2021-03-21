use crypto::{helper::Helper, proofs::keygen::KeyGenerationProof, random::Random};
use hex_literal::hex;
use pallet_mixnet::types::PublicKeyShare;
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
use substrate_subxt::{Client, PairSigner};
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};

use super::substrate::rpc::store_public_key_share;

async fn init() -> Result<Client<NodeTemplateRuntime>, Error> {
    env_logger::init();
    let url = "ws://127.0.0.1:9944";
    let client = ClientBuilder::<NodeTemplateRuntime>::new()
        .set_url(url)
        .build()
        .await?;
    Ok(client)
}

pub async fn keygen(vote: String, sk_as_string: String, sealer: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create private and public key
    let (params, sk, pk) = Helper::setup_lg_system_with_sk(sk_as_string.as_bytes());

    // get the sealer and sealer_id
    let (sealer, sealer_id): (Pair, [u8; 32]) = if sealer == "bob" {
        (
            AccountKeyring::Bob.pair(),
            hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").into(),
        )
    } else {
        (
            AccountKeyring::Charlie.pair(),
            hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22").into(),
        )
    };

    // create public key share + proof
    let r = Random::get_random_less_than(&params.q());
    let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, &sealer_id);
    let pk_share = PublicKeyShare {
        proof: proof.clone().into(),
        pk: pk.h.to_bytes_be(),
    };
    let vote_id = vote.as_bytes().to_vec();

    // setup the vote
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(sealer);
    let store_public_key_share_response =
        store_public_key_share(&client, &signer, vote_id, pk_share).await?;
    println!(
        "store_public_key_share_response: {:?}",
        store_public_key_share_response.events[0].variant
    );

    Ok(())
}

pub async fn decrypt(vote: String, question: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    todo!()
}
