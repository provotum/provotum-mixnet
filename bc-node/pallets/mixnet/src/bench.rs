#![cfg(feature = "runtime-benchmarks")]

use crate::types::{
    Ballot, Cipher, PublicKey as SubstratePK, PublicKeyShare, PublicParameters,
    ShuffleProof as Proof, Topic, TopicId, Vote, VoteId, VotePhase, Wrapper,
};
use crate::{Ballots, Module, Trait};
use alloc::vec::Vec;
use codec::Decode;
use crypto::{
    encryption::ElGamal,
    helper::Helper,
    proofs::{decryption::DecryptionProof, keygen::KeyGenerationProof},
    types::Cipher as BigCipher,
    types::{ElGamalParams, ModuloOperations, PrivateKey, PublicKey as ElGamalPK},
};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_support::{ensure, storage::StorageDoubleMap, traits::Box};
use frame_system::RawOrigin;
use hex_literal::hex;
use num_bigint::BigUint;
use num_traits::One;
use sp_std::vec;

use crate::Module as PalletMixnet;

const NR_OF_SHUFFLES: u8 = 0;

fn get_voting_authority<T: Trait>() -> RawOrigin<T::AccountId> {
    // use Alice as VotingAuthority
    let account_id: [u8; 32] =
        hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d").into();

    let account = T::AccountId::decode(&mut &account_id[..]).unwrap();
    RawOrigin::Signed(account.into())
}

fn get_sealer_bob<T: Trait>() -> (RawOrigin<T::AccountId>, [u8; 32]) {
    let account_id: [u8; 32] =
        hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").into();

    let account = T::AccountId::decode(&mut &account_id[..]).unwrap();
    (RawOrigin::Signed(account.into()), account_id)
}

fn get_sealer_charlie<T: Trait>() -> (RawOrigin<T::AccountId>, [u8; 32]) {
    let account_id: [u8; 32] =
        hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22").into();

    let account = T::AccountId::decode(&mut &account_id[..]).unwrap();
    (RawOrigin::Signed(account.into()), account_id)
}

fn setup_public_key<T: Trait>(
    vote_id: VoteId,
    pk: SubstratePK,
) -> Result<(), &'static str> {
    // use Alice as VotingAuthority
    let who = get_voting_authority::<T>();

    // store created public key and public parameters
    let _setup_result = PalletMixnet::<T>::store_public_key(who.into(), vote_id, pk)?;
    Ok(())
}

fn setup_vote<T: Trait>(
    params: PublicParameters,
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // use Alice as VotingAuthority
    let who = get_voting_authority::<T>();

    // create the vote
    let vote_id = "20201212".as_bytes().to_vec();
    let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

    let topic_id = "20201212-01".as_bytes().to_vec();
    let topic_question = "Moritz for President?".as_bytes().to_vec();
    let topic: Topic = (topic_id.clone(), topic_question);
    let topics = vec![topic];

    PalletMixnet::<T>::create_vote(
        who.into(),
        vote_id.clone(),
        vote_title,
        params,
        topics,
    )?;
    set_vote_phase::<T>(vote_id.clone(), VotePhase::Voting)?;

    Ok((vote_id, topic_id))
}

fn set_vote_phase<T: Trait>(
    vote_id: VoteId,
    vote_phase: VotePhase,
) -> Result<(), &'static str> {
    let voting_authority = get_voting_authority::<T>();
    PalletMixnet::<T>::set_vote_phase(voting_authority.into(), vote_id, vote_phase)?;
    Ok(())
}

fn generate_random_encryptions_encoded<T: Trait>(
    pk: &ElGamalPK,
    q: &BigUint,
    number: usize,
) -> Result<Vec<Cipher>, &'static str> {
    let mut encryptions: Vec<Cipher> = Vec::new();

    for i in 0..number {
        let nr = BigUint::from(i);
        let r = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
        let enc = ElGamal::encrypt_encode(&nr, &r, pk);
        encryptions.push(enc.into());
    }
    Ok(encryptions)
}

fn generate_random_encryptions<T: Trait>(
    pk: &ElGamalPK,
    q: &BigUint,
    number: usize,
) -> Result<Vec<Cipher>, &'static str> {
    let mut encryptions: Vec<Cipher> = Vec::new();
    let mut i: u32 = 0;
    let one = BigUint::one();
    let p = &pk.params.p;

    while encryptions.len() != number {
        let nr = BigUint::from(i);
        if nr.modpow(q, p) == one {
            let r = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
            let enc = ElGamal::encrypt(&nr, &r, pk);
            encryptions.push(enc.into());
        }
        i += 1u32;
    }
    Ok(encryptions)
}

fn setup_shuffle<T: Trait>(
    size: usize,
    encoded: bool,
) -> Result<(Vec<u8>, ElGamalPK, Vec<BigCipher>), &'static str> {
    // setup
    let (params, _, pk) = Helper::setup_lg_system();
    let (vote_id, topic_id) = setup_vote::<T>(params.into())?;
    setup_public_key::<T>(vote_id.clone(), pk.clone().into())?;

    // create messages and random values
    let q = pk.params.q();

    // create the voter (i.e. the transaction signer)
    let account: T::AccountId = whitelisted_caller();
    let voter = RawOrigin::Signed(account.into());

    // generate random encryptions
    let ciphers: Vec<Cipher>;
    if encoded {
        ciphers = generate_random_encryptions_encoded::<T>(&pk, &q, size)?;
    } else {
        ciphers = generate_random_encryptions::<T>(&pk, &q, size)?;
    }

    // ensure the vote phase is Voting -> otherwise Ballots cannot be submitted
    set_vote_phase::<T>(vote_id.clone(), VotePhase::Voting)?;

    for cipher in ciphers.iter() {
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher.clone())];
        let ballot: Ballot = Ballot { answers };
        PalletMixnet::<T>::cast_ballot(voter.clone().into(), vote_id.clone(), ballot)?;
    }

    // type conversion
    let encryptions: Vec<BigCipher> = Wrapper(ciphers).into();
    ensure!(
        encryptions.len() == size,
        "# of votes on chain is not correct"
    );

    Ok((topic_id, pk, encryptions))
}

fn setup_shuffle_proof<T: Trait>(
    size: usize,
    encoded: bool,
) -> Result<
    (
        Vec<u8>,
        Vec<BigCipher>,
        Vec<BigCipher>,
        Vec<BigUint>,
        Vec<usize>,
        ElGamalPK,
    ),
    &'static str,
> {
    let (topic_id, pk, e) = setup_shuffle::<T>(size, encoded)?;
    ensure!(e.len() == size, "# of votes on chain is not correct");

    // shuffle the votes
    let result = PalletMixnet::<T>::shuffle_ciphers(&pk, e.clone());
    let s: (Vec<BigCipher>, Vec<BigUint>, Vec<usize>) = result.unwrap();
    let e_hat = s.0; // the shuffled votes
    let r = s.1; // the re-encryption randoms
    let permutation = s.2;
    Ok((topic_id, e, e_hat, r, permutation, pk))
}

fn setup_sealer<T: Trait>(
    params: &ElGamalParams,
    sk: &PrivateKey,
    pk: &ElGamalPK,
    who: RawOrigin<T::AccountId>,
    vote_id: &VoteId,
    sealer_id: &[u8],
) -> Result<(PublicKeyShare, KeyGenerationProof), &'static str> {
    // create public key share + proof
    let q = &pk.params.q();
    let r = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
    let proof = KeyGenerationProof::generate(params, &sk.x, &pk.h, &r, sealer_id);
    let pk_share = PublicKeyShare {
        proof: proof.clone().into(),
        pk: pk.h.to_bytes_be(),
    };

    // submit the public key share
    PalletMixnet::<T>::store_public_key_share(
        who.into(),
        vote_id.clone(),
        pk_share.clone().into(),
    )?;
    Ok((pk_share, proof))
}

fn setup_vote_with_distributed_keys<T: Trait>(
    size: usize,
    encoded: bool,
) -> Result<
    (
        Vec<u8>,
        Vec<u8>,
        ElGamalPK,  // system public key
        ElGamalPK,  // bob's public key share
        PrivateKey, // bob's private key
        ElGamalPK,  // charlie's public key share
        PrivateKey, // charlie's private key share
    ),
    &'static str,
> {
    // setup the vote and generate intial system parameters
    let (params, _, _) = Helper::setup_lg_system();
    let q = &params.q();
    let (vote_id, topic_id) = setup_vote::<T>(params.clone().into())?;

    // distributed key generation setup
    // Use 1. Sealer: Bob
    let (bob, bob_sealer_id) = get_sealer_bob::<T>();
    let bob_sk_x = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
    let (bob_pk, bob_sk) = Helper::generate_key_pair(&params, &bob_sk_x);
    let (_, _) = setup_sealer::<T>(
        &params,
        &bob_sk,
        &bob_pk,
        bob.clone(),
        &vote_id,
        &bob_sealer_id,
    )?;

    // Use 2. Sealer: Charlie
    let (charlie, charlie_sealer_id) = get_sealer_charlie::<T>();
    let charlie_sk_x = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
    let (charlie_pk, charlie_sk) = Helper::generate_key_pair(&params, &charlie_sk_x);
    let (_, _) = setup_sealer::<T>(
        &params,
        &charlie_sk,
        &charlie_pk,
        charlie,
        &vote_id,
        &charlie_sealer_id,
    )?;

    // combine the public key shares
    let voting_authority = get_voting_authority::<T>();
    PalletMixnet::<T>::combine_public_key_shares(
        voting_authority.clone().into(),
        vote_id.clone(),
    )?;

    // get the public key from the chain
    let system_pk: ElGamalPK = PalletMixnet::<T>::public_key(vote_id.clone())
        .unwrap()
        .into();
    let computed_system_pk: BigUint = bob_pk.h.modmul(&charlie_pk.h, &bob_pk.params.p);
    ensure!(
        system_pk.h == computed_system_pk,
        "public keys are not the same!"
    );

    // create the voter (i.e. the transaction signer)
    let account: T::AccountId = whitelisted_caller();
    let voter = RawOrigin::Signed(account.into());

    // generate random encryptions
    let ciphers: Vec<Cipher>;
    if encoded {
        ciphers = generate_random_encryptions_encoded::<T>(&system_pk, q, size)?;
    } else {
        ciphers = generate_random_encryptions::<T>(&system_pk, q, size)?;
    }

    set_vote_phase::<T>(vote_id.clone(), VotePhase::Voting)?;

    for cipher in ciphers {
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher)];
        let ballot: Ballot = Ballot { answers };
        PalletMixnet::<T>::cast_ballot(voter.clone().into(), vote_id.clone(), ballot)?;
    }

    set_vote_phase::<T>(vote_id.clone(), VotePhase::Tallying)?;

    Ok((
        topic_id, vote_id, system_pk, bob_pk, bob_sk, charlie_pk, charlie_sk,
    ))
}

fn create_decrypted_shares_and_proof<T: Trait>(
    topic_id: &TopicId,
    params: &ElGamalParams,
    sealer_pk: &ElGamalPK,
    sealer_sk: &PrivateKey,
    sealer_id: [u8; 32],
) -> Result<(DecryptionProof, Vec<Vec<u8>>), &'static str> {
    let q = &params.q();

    // fetch the encrypted votes from chain
    let encryptions: Vec<BigCipher> =
        Wrapper(PalletMixnet::<T>::ciphers(topic_id, NR_OF_SHUFFLES)).into();
    ensure!(
        encryptions.len() > 0,
        "the number of encryptions is too low"
    );

    // get sealer's partial decryptions
    let partial_decrytpions = encryptions
        .iter()
        .map(|cipher| ElGamal::partial_decrypt_a(cipher, sealer_sk))
        .collect::<Vec<BigUint>>();

    // convert the decrypted shares: Vec<BigUint> to Vec<Vec<u8>>
    let decrypted_shares: Vec<Vec<u8>> = partial_decrytpions
        .iter()
        .map(|c| c.to_bytes_be())
        .collect::<Vec<Vec<u8>>>();

    // create sealer's proof using sealer's public and private key share
    let r = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
    let decryption_proof = DecryptionProof::generate(
        params,
        &sealer_sk.x,
        &sealer_pk.h.clone().into(),
        &r,
        encryptions,
        partial_decrytpions,
        &sealer_id,
    );
    Ok((decryption_proof, decrypted_shares))
}

fn submit_decrypted_shares_and_proofs<T: Trait>(
    size: usize,
    encoded: bool,
) -> Result<(TopicId, VoteId), &'static str> {
    // setup system with distributed keys
    let (topic_id, vote_id, _, bob_pk, bob_sk, charlie_pk, charlie_sk) =
        setup_vote_with_distributed_keys::<T>(size, encoded)?;

    // use bob
    let (bob, bob_id) = get_sealer_bob::<T>();

    // create bob's decrypted shares + proof using bob's public and private key share
    let (bob_proof, bob_shares) = create_decrypted_shares_and_proof::<T>(
        &topic_id,
        &bob_pk.params,
        &bob_pk,
        &bob_sk,
        bob_id,
    )?;

    // submit bob's proof + shares
    PalletMixnet::<T>::submit_decrypted_shares(
        bob.into(),
        vote_id.clone(),
        topic_id.clone(),
        bob_shares,
        bob_proof.into(),
        NR_OF_SHUFFLES,
    )?;

    // use charlie
    let (charlie, charlie_id) = get_sealer_charlie::<T>();

    // create charlie's decrypted shares + proof using charlie's public and private key share
    let (charlie_proof, charlie_shares) = create_decrypted_shares_and_proof::<T>(
        &topic_id,
        &charlie_pk.params,
        &charlie_pk,
        &charlie_sk,
        charlie_id,
    )?;

    // submit charlie's proof + shares
    PalletMixnet::<T>::submit_decrypted_shares(
        charlie.into(),
        vote_id.clone(),
        topic_id.clone(),
        charlie_shares,
        charlie_proof.into(),
        NR_OF_SHUFFLES,
    )?;
    Ok((topic_id, vote_id))
}

benchmarks! {
    _{ }

    store_public_key {
        let (_, _, pk) = Helper::setup_lg_system();
        let who = get_voting_authority::<T>();
        let vote_id = "20201212".as_bytes().to_vec();
    }: {
        // store created public key and public parameters
        let _result = PalletMixnet::<T>::store_public_key(who.into(), vote_id.clone(), pk.clone().into());
    }
    verify {
        // fetch the public key from the chain
        let pk_from_chain: ElGamalPK = PalletMixnet::<T>::public_key(vote_id).unwrap().into();
        ensure!(pk_from_chain == pk, "fail pk_from_chain != pk");
    }

    store_public_key_share {
        let (params, sk, pk) = Helper::setup_lg_system();
        let (bob, bob_id) = get_sealer_bob::<T>();
        let (vote_id, _) = setup_vote::<T>(params.clone().into())?;

        // create public key share + proof
        let q = &params.clone().q();
        let random = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
        let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &random, &bob_id);
        let pk_share = PublicKeyShare {
            proof: proof.clone().into(),
            pk: pk.h.to_bytes_be(),
        };
    }: {
        // store created public key and public parameters
        let _result = PalletMixnet::<T>::store_public_key_share(bob.into(), vote_id.clone(), pk_share.clone().into());
    }

    combine_public_key_shares {
        let (params, sk, pk) = Helper::setup_lg_system();
        let voting_authority = get_voting_authority::<T>();
        let (vote_id, _) = setup_vote::<T>(params.clone().into())?;
        let q = &params.clone().q();

        // create public key share + proof for bob
        let (bob, bob_id) = get_sealer_bob::<T>();
        let random = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
        let proof_bob = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &random, &bob_id);
        let pk_share_bob = PublicKeyShare {
            proof: proof_bob.clone().into(),
            pk: pk.h.to_bytes_be(),
        };
        // store created public key and public parameters
        let result_ = PalletMixnet::<T>::store_public_key_share(bob.into(), vote_id.clone(), pk_share_bob.clone().into());

        // create public key share + proof for charlie
        let (charlie, charlie_id) = get_sealer_charlie::<T>();
        let random = PalletMixnet::<T>::get_random_biguint_less_than(q)?;
        let proof_charlie = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &random, &charlie_id);
        let pk_share_charlie = PublicKeyShare {
            proof: proof_charlie.clone().into(),
            pk: pk.h.to_bytes_be(),
        };
        // store created public key and public parameters
        let result_ = PalletMixnet::<T>::store_public_key_share(charlie.into(), vote_id.clone(), pk_share_charlie.clone().into());
    }: {
        // combine the public key shares
        let _result = PalletMixnet::<T>::combine_public_key_shares(voting_authority.into(), vote_id.clone())?;
    }

    create_vote {
        // use Alice as VotingAuthority
        let who = get_voting_authority::<T>();

        // create the vote
        let vote_id = "20201212".as_bytes().to_vec();
        let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

        let topic_id = "20201212-01".as_bytes().to_vec();
        let topic_question = "Moritz for President?".as_bytes().to_vec();
        let topic: Topic = (topic_id.clone(), topic_question);
        let topics = vec![topic];

        // store created public key
        let (params, _, pk) = Helper::setup_lg_system();
        PalletMixnet::<T>::store_public_key(who.clone().into(), vote_id.clone(), pk.into())?;

    }: {
        let _result = PalletMixnet::<T>::create_vote(who.into(), vote_id.clone(), vote_title.clone(), params.into(), topics)?;
    } verify {
        let vote: Vote<T::AccountId> = PalletMixnet::<T>::votes(vote_id);
        ensure!(vote_title == vote.title, "title are not the same!");
    }

    store_question {
        let (params, _, pk) = Helper::setup_lg_system();
        let (vote_id, topic_id) = setup_vote::<T>(params.into())?;

        // use Alice as VotingAuthority
        let who = get_voting_authority::<T>();

        // create another topic
        let topic_id_2 = "20201212-02".as_bytes().to_vec();
        let topic_question = "Moritz for King?".as_bytes().to_vec();
        let topic: Topic = (topic_id_2.clone(), topic_question.clone());
    }: {
        let _result = PalletMixnet::<T>::store_question(who.into(), vote_id.clone(), topic);
    } verify {
        let topic_: Vec<Topic> = PalletMixnet::<T>::topics(vote_id);
        ensure!(topic_id == topic_[0].0, "topic ids are not the same!");
        ensure!(topic_id_2 == topic_[1].0, "topic ids are not the same!");
        ensure!(topic_question == topic_[1].1, "topic questions are not the same!");
    }

    cast_ballot {
        // setup
        let (params, _, pk) = Helper::setup_lg_system();
        let (vote_id, topic_id) = setup_vote::<T>(params.into())?;

        // create messages and random values
        let q = &pk.params.q();
        let message = BigUint::one();
        let random = PalletMixnet::<T>::get_random_biguint_less_than(q)?;

        // create the voter (i.e. the transaction signer)
        let account: T::AccountId = whitelisted_caller();
        let voter = RawOrigin::Signed(account.clone().into());

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let cipher: Cipher = ElGamal::encrypt_encode(&message, &random, &pk).into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id, cipher)];
        let ballot: Ballot = Ballot { answers };
    }: {
        let _result = PalletMixnet::<T>::cast_ballot(voter.clone().into(), vote_id.clone(), ballot.clone())?;
    } verify {
        let ballot_: Ballot = Ballots::<T>::get(vote_id, account);
        ensure!(ballot == ballot_, "ballots are not the same!");
    }

    verify_public_key_share_proof {
        // setup
        let (params, sk, pk) = Helper::setup_lg_system();
        let q = params.q();
        let (vote_id, topic_id) = setup_vote::<T>(params.clone().into())?;

        // create the sealer
        let sealer_id: [u8; 32] =
        hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").into();
        let sealer_account_id = T::AccountId::decode(&mut &sealer_id[..]).unwrap();
        let sealer = RawOrigin::Signed(sealer_account_id.into());

        // create public key share + proof
        let r = PalletMixnet::<T>::get_random_biguint_less_than(&q)?;
        let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, &sealer_id);
        let pk_share = PublicKeyShare {
            proof: proof.clone().into(),
            pk: pk.h.to_bytes_be(),
        };

    }: {
        PalletMixnet::<T>::store_public_key_share(sealer.into(), vote_id, pk_share.clone())?;
    }

    shuffle_ciphers_3 {
        let (_, pk, e) = setup_shuffle::<T>(3, false)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_10 {
        let (_, pk, e) = setup_shuffle::<T>(10, false)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_30 {
        let (_, pk, e) = setup_shuffle::<T>(30, false)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_100 {
        let (_, pk, e) = setup_shuffle::<T>(100, false)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_1000 {
        let (_, pk, e) = setup_shuffle::<T>(1000, false)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_3_encoded {
        let (_, pk, e) = setup_shuffle::<T>(3, true)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_10_encoded {
        let (_, pk, e) = setup_shuffle::<T>(10, true)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_30_encoded {
        let (_, pk, e) = setup_shuffle::<T>(30, true)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_100_encoded {
        let (_, pk, e) = setup_shuffle::<T>(100, true)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_ciphers_1000_encoded {
        let (_, pk, e) = setup_shuffle::<T>(1000, true)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&pk, e);
    }

    shuffle_proof_3 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(3, false)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_10 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(10, false)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_30 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(30, false)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_100 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(100, false)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_1000 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(1000, false)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_3_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(3, true)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_10_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(10, true)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_30_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(30, true)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_100_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(100, true)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_1000_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(1000, true)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e, e_hat, r, &permutation, &pk);
    }

    verify_shuffle_proof_3 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(3, false)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_10 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(10, false)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_30 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(30, false)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_100 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(100, false)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_1000 {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(1000, false)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_3_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(3, true)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_10_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(10, true)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_30_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(30, true)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_100_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(100, true)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_1000_encoded {
        let (topic_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(1000, true)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&topic_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&topic_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_submit_decrypted_shares_100 {
        // setup system with distributed keys
        let (topic_id, vote_id, system_pk, bob_pk, bob_sk, charlie_pk, charlie_sk) = setup_vote_with_distributed_keys::<T>(100, false)?;

        // use bob
        let (bob, bob_id) = get_sealer_bob::<T>();

        // create bob's decrypted shares + proof using bob's public and private key share
        let (bob_proof, bob_shares) = create_decrypted_shares_and_proof::<T>(&topic_id, &bob_pk.params, &bob_pk, &bob_sk, bob_id)?;
    }: {
        let _success = PalletMixnet::<T>::submit_decrypted_shares(
            bob.into(),
            vote_id,
            topic_id,
            bob_shares,
            bob_proof.into(), NR_OF_SHUFFLES
        )?;
    }

    verify_submit_decrypted_shares_1000 {
        // setup system with distributed keys
        let (topic_id, vote_id, system_pk, bob_pk, bob_sk, charlie_pk, charlie_sk) = setup_vote_with_distributed_keys::<T>(1000, false)?;

        // use bob
        let (bob, bob_id) = get_sealer_bob::<T>();

        // create bob's decrypted shares + proof using bob's public and private key share
        let (bob_proof, bob_shares) = create_decrypted_shares_and_proof::<T>(&topic_id, &bob_pk.params, &bob_pk, &bob_sk, bob_id)?;
    }: {
        let _success = PalletMixnet::<T>::submit_decrypted_shares(
            bob.into(),
            vote_id,
            topic_id,
            bob_shares,
            bob_proof.into(), NR_OF_SHUFFLES
        )?;
    }

    verify_submit_decrypted_shares_10000 {
        // setup system with distributed keys
        let (topic_id, vote_id, system_pk, bob_pk, bob_sk, charlie_pk, charlie_sk) = setup_vote_with_distributed_keys::<T>(10000, false)?;

        // use bob
        let (bob, bob_id) = get_sealer_bob::<T>();

        // create bob's decrypted shares + proof using bob's public and private key share
        let (bob_proof, bob_shares) = create_decrypted_shares_and_proof::<T>(&topic_id, &bob_pk.params, &bob_pk, &bob_sk, bob_id)?;
    }: {
        let _success = PalletMixnet::<T>::submit_decrypted_shares(
            bob.into(),
            vote_id,
            topic_id,
            bob_shares,
            bob_proof.into(), NR_OF_SHUFFLES
        )?;
    }

    verify_submit_decrypted_shares_100_encoded {
        // setup system with distributed keys
        let (topic_id, vote_id, system_pk, bob_pk, bob_sk, charlie_pk, charlie_sk) = setup_vote_with_distributed_keys::<T>(100, true)?;

        // use bob
        let (bob, bob_id) = get_sealer_bob::<T>();

        // create bob's decrypted shares + proof using bob's public and private key share
        let (bob_proof, bob_shares) = create_decrypted_shares_and_proof::<T>(&topic_id, &bob_pk.params, &bob_pk, &bob_sk, bob_id)?;
    }: {
        let _success = PalletMixnet::<T>::submit_decrypted_shares(
            bob.into(),
            vote_id,
            topic_id,
            bob_shares,
            bob_proof.into(), NR_OF_SHUFFLES
        )?;
    }

    verify_submit_decrypted_shares_1000_encoded {
        // setup system with distributed keys
        let (topic_id, vote_id, system_pk, bob_pk, bob_sk, charlie_pk, charlie_sk) = setup_vote_with_distributed_keys::<T>(1000, true)?;

        // use bob
        let (bob, bob_id) = get_sealer_bob::<T>();

        // create bob's decrypted shares + proof using bob's public and private key share
        let (bob_proof, bob_shares) = create_decrypted_shares_and_proof::<T>(&topic_id, &bob_pk.params, &bob_pk, &bob_sk, bob_id)?;
    }: {
        let _success = PalletMixnet::<T>::submit_decrypted_shares(
            bob.into(),
            vote_id,
            topic_id,
            bob_shares,
            bob_proof.into(), NR_OF_SHUFFLES
        )?;
    }

    combine_decrypted_shares_100 {
        // setup everything including keys, votes, decrypted shares
        let (topic_id, vote_id) = submit_decrypted_shares_and_proofs::<T>(100, false)?;

        // use Alice as VotingAuthority to combine the votes
        let who = get_voting_authority::<T>();
    }: {
        let _success = PalletMixnet::<T>::combine_decrypted_shares(
            who.into(),
            vote_id,
            topic_id,
            false, NR_OF_SHUFFLES
        )?;
    }

    combine_decrypted_shares_1000 {
        // setup everything including keys, votes, decrypted shares
        let (topic_id, vote_id) = submit_decrypted_shares_and_proofs::<T>(1000, false)?;

        // use Alice as VotingAuthority to combine the votes
        let who = get_voting_authority::<T>();
    }: {
        let _success = PalletMixnet::<T>::combine_decrypted_shares(
            who.into(),
            vote_id,
            topic_id,
            false, NR_OF_SHUFFLES
        )?;
    }

    combine_decrypted_shares_10000 {
        // setup everything including keys, votes, decrypted shares
        let (topic_id, vote_id) = submit_decrypted_shares_and_proofs::<T>(10000, false)?;

        // use Alice as VotingAuthority to combine the votes
        let who = get_voting_authority::<T>();
    }: {
        let _success = PalletMixnet::<T>::combine_decrypted_shares(
            who.into(),
            vote_id,
            topic_id,
            false, NR_OF_SHUFFLES
        )?;
    }

    combine_decrypted_shares_100_encoded {
        // setup everything including keys, votes, decrypted shares
        let (topic_id, vote_id) = submit_decrypted_shares_and_proofs::<T>(100, true)?;

        // use Alice as VotingAuthority to combine the votes
        let who = get_voting_authority::<T>();
    }: {
        let _success = PalletMixnet::<T>::combine_decrypted_shares(
            who.into(),
            vote_id,
            topic_id,
            false, NR_OF_SHUFFLES
        )?;
    }

    combine_decrypted_shares_1000_encoded {
        // setup everything including keys, votes, decrypted shares
        let (topic_id, vote_id) = submit_decrypted_shares_and_proofs::<T>(1000, true)?;

        // use Alice as VotingAuthority to combine the votes
        let who = get_voting_authority::<T>();
    }: {
        let _success = PalletMixnet::<T>::combine_decrypted_shares(
            who.into(),
            vote_id,
            topic_id,
            false, NR_OF_SHUFFLES
        )?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{ExternalityBuilder, TestRuntime};
    use frame_support::assert_ok;

    #[test]
    fn test_benchmarks() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_store_public_key::<TestRuntime>());
            assert_ok!(test_benchmark_store_public_key_share::<TestRuntime>());
            assert_ok!(test_benchmark_combine_public_key_shares::<TestRuntime>());
            assert_ok!(test_benchmark_store_question::<TestRuntime>());
            assert_ok!(test_benchmark_create_vote::<TestRuntime>());
            assert_ok!(test_benchmark_cast_ballot::<TestRuntime>());
        });
    }

    #[test]
    fn test_benchmarks_shuffle_ciphers() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_shuffle_ciphers_3::<TestRuntime>());
            assert_ok!(test_benchmark_shuffle_ciphers_3_encoded::<TestRuntime>());
        });
    }

    #[test]
    fn test_benchmarks_shuffle_proof() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_shuffle_proof_3::<TestRuntime>());
            assert_ok!(test_benchmark_verify_shuffle_proof_3::<TestRuntime>());
        });
    }

    #[test]
    fn test_benchmarks_shuffle_proof_encoded() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_shuffle_proof_3_encoded::<TestRuntime>());
            assert_ok!(test_benchmark_verify_shuffle_proof_3_encoded::<TestRuntime>());
        });
    }

    #[test]
    fn test_benchmarks_submit_decrypted_shares() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_verify_submit_decrypted_shares_100::<
                TestRuntime,
            >());
        });
    }

    #[test]
    fn test_benchmarks_submit_decrypted_shares_encoded() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_verify_submit_decrypted_shares_100_encoded::<
                TestRuntime,
            >());
        });
    }

    #[test]
    fn test_benchmarks_combine_decrypted_shares() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_combine_decrypted_shares_100::<TestRuntime>());
        });
    }

    #[test]
    fn test_benchmarks_combine_decrypted_shares_encoded() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_combine_decrypted_shares_100_encoded::<
                TestRuntime,
            >());
        });
    }
}
