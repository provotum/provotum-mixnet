use crypto::{
    encryption::ElGamal,
    helper::Helper,
    proofs::{decryption::DecryptionProof, keygen::KeyGenerationProof},
    random::Random,
    types::Cipher as BigCipher,
};
use hex_literal::hex;
use num_bigint::BigUint;
use pallet_mixnet::types::{Cipher, PublicKeyShare, Wrapper};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
use substrate_subxt::{Client, PairSigner};
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};

use super::substrate::rpc::{get_ciphers, store_public_key_share, submit_partial_decryptions};

async fn init() -> Result<Client<NodeTemplateRuntime>, Error> {
    env_logger::init();
    let url = "ws://127.0.0.1:9944";
    let client = ClientBuilder::<NodeTemplateRuntime>::new()
        .set_url(url)
        .build()
        .await?;
    Ok(client)
}

fn get_sealer(sealer: String) -> (Pair, [u8; 32]) {
    // get the sealer and sealer_id
    if sealer == "bob" {
        return (
            AccountKeyring::Bob.pair(),
            hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").into(),
        );
    } else {
        return (
            AccountKeyring::Charlie.pair(),
            hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22").into(),
        );
    };
}

pub async fn keygen(vote: String, sk_as_string: String, sealer: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create private and public key
    let (params, sk, pk) = Helper::setup_lg_system_with_sk(sk_as_string.as_bytes());

    // get the sealer and sealer_id
    let (sealer, sealer_id): (Pair, [u8; 32]) = get_sealer(sealer);

    // create public key share + proof
    let r = Random::get_random_less_than(&params.q());
    let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, &sealer_id);
    let pk_share = PublicKeyShare {
        proof: proof.clone().into(),
        pk: pk.h.to_bytes_be(),
    };
    let vote_id = vote.as_bytes().to_vec();

    // submit the public key share + proof
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(sealer);
    let store_public_key_share_response =
        store_public_key_share(&client, &signer, vote_id, pk_share).await?;
    println!(
        "store_public_key_share_response: {:?}",
        store_public_key_share_response.events[0].variant
    );

    Ok(())
}

pub async fn decrypt(
    vote: String,
    question: String,
    sk_as_string: String,
    sealer: String,
) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    // create private and public key
    let (params, sk, pk) = Helper::setup_lg_system_with_sk(sk_as_string.as_bytes());

    // get the sealer and sealer_id
    let (sealer, sealer_id): (Pair, [u8; 32]) = get_sealer(sealer);

    // fetch the encrypted votes from chain
    let vote_id = vote.as_bytes().to_vec();
    let topic_id = question.as_bytes().to_vec();
    let nr_of_shuffles = 3;
    let encryptions: Vec<Cipher> = get_ciphers(&client, topic_id.clone(), nr_of_shuffles).await?;
    let encryptions: Vec<BigCipher> = Wrapper(encryptions).into();

    // get partial decryptions
    let partial_decryptions = encryptions
        .iter()
        .map(|cipher| ElGamal::partial_decrypt_a(cipher, &sk))
        .collect::<Vec<BigUint>>();

    // convert the decrypted shares: Vec<BigUint> to Vec<Vec<u8>>
    let shares: Vec<Vec<u8>> = partial_decryptions
        .iter()
        .map(|c| c.to_bytes_be())
        .collect::<Vec<Vec<u8>>>();

    // create proof using public and private key share
    let r = Random::get_random_less_than(&params.q());
    let proof = DecryptionProof::generate(
        &params,
        &sk.x,
        &pk.h.into(),
        &r,
        encryptions,
        partial_decryptions,
        &sealer_id,
    );

    // submit the partial decryption + proof
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(sealer);
    let response = submit_partial_decryptions(
        &client,
        &signer,
        vote_id,
        topic_id,
        shares,
        proof.into(),
        nr_of_shuffles,
    )
    .await?;
    println!("response: {:?}", response.events[0].variant);

    Ok(())
}
