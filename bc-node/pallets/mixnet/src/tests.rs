use crate::mock::*;
use crate::types::{
    Ballot, Cipher, PublicKey as SubstratePK, PublicParameters, ShuffleProof as Proof, VotePhase,
    Wrapper,
};
use crate::*;
use codec::Decode;
use crypto::{
    encryption::ElGamal,
    helper::Helper,
    types::{
        Cipher as BigCipher, ElGamalParams, ModuloOperations, PrivateKey, PublicKey as ElGamalPK,
    },
};
use frame_support::{assert_err, assert_ok};
use frame_system as system;
use hex_literal::hex;
use num_bigint::BigUint;
use num_traits::Zero;
use sp_std::vec;

fn get_voting_authority() -> Origin {
    // use Alice as VotingAuthority
    let account_id: [u8; 32] =
        hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d").into();
    let account = <TestRuntime as system::Trait>::AccountId::decode(&mut &account_id[..]).unwrap();
    Origin::signed(account)
}

fn get_sealer_bob() -> (Origin, <TestRuntime as system::Trait>::AccountId, [u8; 32]) {
    let account_id: [u8; 32] =
        hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").into();

    let sealer: <TestRuntime as system::Trait>::AccountId =
        <TestRuntime as system::Trait>::AccountId::decode(&mut &account_id[..]).unwrap();
    (Origin::signed(sealer), sealer, account_id)
}

fn get_sealer_charlie() -> (Origin, <TestRuntime as system::Trait>::AccountId, [u8; 32]) {
    let account_id: [u8; 32] =
        hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22").into();

    let sealer: <TestRuntime as system::Trait>::AccountId =
        <TestRuntime as system::Trait>::AccountId::decode(&mut &account_id[..]).unwrap();
    (Origin::signed(sealer), sealer, account_id)
}

fn setup_sealer(
    params: &ElGamalParams,
    sk: &PrivateKey,
    pk: &ElGamalPK,
    who: Origin,
    vote_id: &VoteId,
    sealer_id: &[u8],
) -> (PublicKeyShare, KeyGenerationProof) {
    // create public key share + proof
    let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
    let proof = KeyGenerationProof::generate(params, &sk.x, &pk.h, &r, sealer_id);
    let pk_share = PublicKeyShare {
        proof: proof.clone().into(),
        pk: pk.h.to_bytes_be(),
    };

    // submit the public key share
    assert_ok!(OffchainModule::store_public_key_share(
        who,
        vote_id.clone(),
        pk_share.clone().into()
    ));
    (pk_share, proof)
}

fn setup_public_key(vote_id: VoteId, pk: SubstratePK) {
    // use Alice as VotingAuthority
    let who = get_voting_authority();

    // store created public key and public parameters
    let public_key_storage = OffchainModule::store_public_key(who, vote_id, pk);
    assert_ok!(public_key_storage);
}

fn setup_vote(params: PublicParameters) -> (Vec<u8>, Vec<u8>) {
    // use Alice as VotingAuthority
    let who = get_voting_authority();

    // create the vote
    let vote_id = "20201212".as_bytes().to_vec();
    let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

    let topic_id = "20201212-01".as_bytes().to_vec();
    let topic_question = "Moritz for President?".as_bytes().to_vec();
    let topic: Topic = (topic_id.clone(), topic_question);
    let topics = vec![topic];

    let vote_created =
        OffchainModule::create_vote(who, vote_id.clone(), vote_title, params, topics);
    assert_ok!(vote_created);
    (vote_id, topic_id)
}

fn shuffle_proof_test(vote_id: Vec<u8>, topic_id: Vec<u8>, pk: ElGamalPK, encoded: bool) -> bool {
    // store created public key and public parameters
    setup_public_key(vote_id.clone(), pk.clone().into());

    let messages = vec![
        BigUint::from(0u32),
        BigUint::from(1u32),
        BigUint::from(2u32),
        BigUint::from(0u32),
        BigUint::from(1u32),
        BigUint::from(2u32),
    ];

    // encrypt the message -> encrypted message
    // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
    let randoms = vec![b"08", b"17", b"01", b"16", b"11", b"00"];
    assert_eq!(messages.len(), randoms.len());

    // create the voter (i.e. the transaction signer)
    let account: <TestRuntime as system::Trait>::AccountId = Default::default();
    let voter = Origin::signed(account);

    for index in 0..messages.len() {
        let random = BigUint::parse_bytes(randoms[index], 10).unwrap();

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let cipher: Cipher;
        if encoded {
            cipher = ElGamal::encrypt_encode(&messages[index], &random, &pk).into();
        } else {
            cipher = ElGamal::encrypt(&messages[index], &random, &pk).into();
        }
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher)];
        let ballot: Ballot = Ballot { answers };

        let vote_submission_result =
            OffchainModule::cast_ballot(voter.clone(), vote_id.clone(), ballot);
        assert_ok!(vote_submission_result);
    }

    // get the encrypted votes
    let big_ciphers_from_chain: Vec<BigCipher> = Wrapper(OffchainModule::ciphers(&topic_id)).into();
    assert!(big_ciphers_from_chain.len() > 0);

    // shuffle the votes
    let shuffle_result = OffchainModule::shuffle_ciphers(&vote_id, &topic_id);
    let shuffled: (Vec<BigCipher>, Vec<BigUint>, Vec<usize>) = shuffle_result.unwrap();
    let shuffled_ciphers = shuffled.0;
    let re_encryption_randoms = shuffled.1;
    let permutation = &shuffled.2;

    // TEST
    // GENERATE PROOF
    let result = OffchainModule::generate_shuffle_proof(
        &vote_id,
        big_ciphers_from_chain.clone(),
        shuffled_ciphers.clone(),
        re_encryption_randoms,
        permutation,
        &pk,
    );
    let proof: Proof = result.unwrap();

    // VERIFY PROOF
    let verification = OffchainModule::verify_shuffle_proof(
        &vote_id,
        proof,
        big_ciphers_from_chain,
        shuffled_ciphers,
        &pk,
    );
    let is_proof_valid = verification.unwrap();
    is_proof_valid
}

#[test]
fn test_setup_public_key_work() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (_, _, pk) = Helper::setup_sm_system();
        let vote_id = "20201212".as_bytes().to_vec();
        setup_public_key(vote_id, pk.into());
    });
}

#[test]
fn test_setup_vote_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, _) = Helper::setup_sm_system();
        setup_vote(params.into());
    });
}

#[test]
fn test_initialization_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Fetch Voting Authority
        let voting_authorities = OffchainModule::voting_authorities();
        assert!(voting_authorities.len() == 1);

        // Fetch Sealers
        let sealers = OffchainModule::sealers();
        assert!(sealers.len() == 3);
    });
}

#[test]
fn test_store_public_key() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // use Alice as VotingAuthority
        let who = get_voting_authority();
        let vote_id = "20201212".as_bytes().to_vec();

        // create the public key
        let (_, _, pk) = Helper::setup_md_system();

        // store created public key and public parameters
        let public_key_storage =
            OffchainModule::store_public_key(who, vote_id.clone(), pk.clone().into());
        assert_ok!(public_key_storage);

        // fetch the public key from the chain
        let pk_from_chain: ElGamalPK = OffchainModule::public_key(vote_id).unwrap().into();
        assert_eq!(pk_from_chain, pk);
    });
}

#[test]
fn test_store_public_key_not_a_voting_authority() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create the submitter (i.e. the default voter)
        // NOT a voting authority
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let who = Origin::signed(account);
        let vote_id = "20201212".as_bytes().to_vec();

        // create the public key
        let (_, _, pk) = Helper::setup_md_system();

        // try to store public key
        assert_err!(
            OffchainModule::store_public_key(who, vote_id, pk.clone().into()),
            Error::<TestRuntime>::NotAVotingAuthority
        )
    });
}

#[test]
fn test_fetch_public_key_does_not_exist() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // fetch the public key from the chain which doesn't exist
        let vote_id = "20201212".as_bytes().to_vec();
        let pk_from_chain: Option<SubstratePK> = OffchainModule::public_key(vote_id);
        assert_eq!(pk_from_chain, None);
    });
}

#[test]
fn test_create_vote_not_a_voting_authority() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create the submitter (i.e. the default voter)
        // NOT a voting authority
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let who = Origin::signed(account);

        // create the vote
        let (params, _, _) = Helper::setup_sm_system();
        let vote_id = "20201212".as_bytes().to_vec();
        let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

        let topic_id = "20201212-01".as_bytes().to_vec();
        let topic_question = "Moritz for President?".as_bytes().to_vec();
        let topic: Topic = (topic_id, topic_question);
        let topics = vec![topic];

        assert_err!(
            OffchainModule::create_vote(who, vote_id, vote_title, params.into(), topics),
            Error::<TestRuntime>::NotAVotingAuthority
        )
    });
}
#[test]
fn test_create_vote_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create the submitter (i.e. the voting_authority)
        // use Alice as VotingAuthority
        let who = get_voting_authority();

        // create the vote
        let (params, _, _) = Helper::setup_sm_system();
        let vote_id = "20201212".as_bytes().to_vec();
        let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

        let topic_id = "20201212-01".as_bytes().to_vec();
        let topic_question = "Moritz for President?".as_bytes().to_vec();
        let topic: Topic = (topic_id, topic_question);
        let topics = vec![topic];

        let vote_created =
            OffchainModule::create_vote(who, vote_id, vote_title, params.into(), topics);
        assert_ok!(vote_created);
    });
}

#[test]
fn test_store_question_not_a_voting_authority() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create fake authority
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let who = Origin::signed(account);

        // create fake vote_id
        let vote_id = "fake vote id".as_bytes().to_vec();

        // Create A New Topic
        let new_topic_id = "20201212-02".as_bytes().to_vec();
        let topic_question = "Moritz for King?".as_bytes().to_vec();
        let topic: Topic = (new_topic_id.clone(), topic_question);

        // Try to store the Topic (Question)
        assert_err!(
            OffchainModule::store_question(who, vote_id, topic),
            Error::<TestRuntime>::NotAVotingAuthority
        );
    });
}

#[test]
fn test_store_question_no_vote_exists() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create the submitter (i.e. the voting_authority)
        // use Alice as VotingAuthority
        let who = get_voting_authority();

        // create fake vote_id
        let vote_id = "fake vote id".as_bytes().to_vec();

        // Create A New Topic
        let new_topic_id = "20201212-02".as_bytes().to_vec();
        let topic_question = "Moritz for King?".as_bytes().to_vec();
        let topic: Topic = (new_topic_id.clone(), topic_question);

        // Try to store the Topic (Question)
        assert_err!(
            OffchainModule::store_question(who, vote_id, topic),
            Error::<TestRuntime>::VoteDoesNotExist
        );
    });
}

#[test]
fn test_store_question_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create the submitter (i.e. the voting_authority)
        // use Alice as VotingAuthority
        let who = get_voting_authority();

        // Setup Vote & Store initial Topic
        let (params, _, _) = Helper::setup_sm_system();
        let (vote_id, topic_id) = setup_vote(params.into());

        // Create A New Topic
        let new_topic_id = "20201212-02".as_bytes().to_vec();
        let topic_question = "Moritz for King?".as_bytes().to_vec();
        let topic: Topic = (new_topic_id.clone(), topic_question);

        // Store the Topic (Question)
        let question_stored = OffchainModule::store_question(who, vote_id.clone(), topic);
        assert_ok!(question_stored);

        let topics = OffchainModule::topics(vote_id);
        assert_eq!(topics.len(), 2usize);
        assert_eq!(topics[0].0, topic_id);
        assert_eq!(topics[1].0, new_topic_id);
    });
}

#[test]
fn test_cast_ballot_no_vote_exists() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // use the default voter
        let acct: <TestRuntime as system::Trait>::AccountId = Default::default();

        // create not existing topic_id and vote_id
        let topic_id = "Topic Doesn't Exist".as_bytes().to_vec();
        let vote_id = "Vote Doesn't Exist".as_bytes().to_vec();

        // create fake cipher & ballot
        let cipher = Cipher {
            a: "1".as_bytes().to_vec(),
            b: "2".as_bytes().to_vec(),
        };
        let answers = vec![(topic_id, cipher)];
        let ballot: Ballot = Ballot { answers };
        assert_err!(
            OffchainModule::cast_ballot(Origin::signed(acct), vote_id.clone(), ballot.clone()),
            Error::<TestRuntime>::VoteDoesNotExist
        );
    });
}

#[test]
fn test_cast_ballot_works_encoded() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup Public Key
        let (params, _, pk) = Helper::setup_sm_system();
        let q = &params.q();

        // Setup Vote
        let (vote_id, topic_id) = setup_vote(params.into());
        setup_public_key(vote_id.clone(), pk.clone().into());

        // Create the voter
        let acct: <TestRuntime as system::Trait>::AccountId = Default::default();

        // submit the value 32
        let num: u64 = 32;
        let big: BigUint = BigUint::from(num);
        let r = OffchainModule::get_random_biguint_less_than(q).unwrap();

        // use additive homomorphic encoding for message i.e. g^m
        let cipher: Cipher = ElGamal::encrypt_encode(&big, &r, &pk).into();
        let answers = vec![(topic_id.clone(), cipher.clone())];
        let ballot: Ballot = Ballot { answers };

        // Test
        // call cast_ballot
        assert_ok!(OffchainModule::cast_ballot(
            Origin::signed(acct),
            vote_id.clone(),
            ballot.clone()
        ));
        let ballot_from_chain = OffchainModule::ballots(vote_id.clone(), acct);
        // A encrypted ballot is inserted to Ballots vec
        assert_eq!(ballot_from_chain, ballot.clone());

        // Cipher is inserted into Ciphers
        assert_eq!(
            OffchainModule::ciphers(topic_id.clone()),
            vec![cipher.clone()]
        );

        // An event is emitted
        assert!(System::events().iter().any(|er| er.event
            == TestEvent::pallet_mixnet(RawEvent::BallotSubmitted(
                acct,
                vote_id.clone(),
                ballot.clone()
            ))));

        // Insert another ballot
        let ballot2 = ballot.clone();
        assert_ok!(OffchainModule::cast_ballot(
            Origin::signed(acct),
            vote_id.clone(),
            ballot.clone()
        ));
        // A encrypted ballot is inserted to Ballots vec
        assert_eq!(OffchainModule::ballots(vote_id, acct), ballot2.clone());

        // Cipher is inserted into Ciphers
        assert_eq!(
            OffchainModule::ciphers(topic_id.clone()),
            vec![cipher.clone(), cipher]
        );
    });
}

#[test]
fn test_cast_ballot_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup Public Key
        let (params, _, pk) = Helper::setup_sm_system();
        let q = &params.q();

        // Setup Vote
        let (vote_id, topic_id) = setup_vote(params.into());
        setup_public_key(vote_id.clone(), pk.clone().into());

        // Create the voter
        let acct: <TestRuntime as system::Trait>::AccountId = Default::default();

        // submit the value 32
        let num: u64 = 32;
        let big: BigUint = BigUint::from(num);
        let r = OffchainModule::get_random_biguint_less_than(q).unwrap();
        let cipher: Cipher = ElGamal::encrypt(&big, &r, &pk).into();
        let answers = vec![(topic_id.clone(), cipher.clone())];
        let ballot: Ballot = Ballot { answers };

        // Test
        // call cast_ballot
        assert_ok!(OffchainModule::cast_ballot(
            Origin::signed(acct),
            vote_id.clone(),
            ballot.clone()
        ));
        let ballot_from_chain = OffchainModule::ballots(vote_id.clone(), acct);
        // A encrypted ballot is inserted to Ballots vec
        assert_eq!(ballot_from_chain, ballot.clone());

        // Cipher is inserted into Ciphers
        assert_eq!(
            OffchainModule::ciphers(topic_id.clone()),
            vec![cipher.clone()]
        );

        // An event is emitted
        assert!(System::events().iter().any(|er| er.event
            == TestEvent::pallet_mixnet(RawEvent::BallotSubmitted(
                acct,
                vote_id.clone(),
                ballot.clone()
            ))));

        // Insert another ballot
        let ballot2 = ballot.clone();
        assert_ok!(OffchainModule::cast_ballot(
            Origin::signed(acct),
            vote_id.clone(),
            ballot.clone()
        ));
        // A encrypted ballot is inserted to Ballots vec
        assert_eq!(OffchainModule::ballots(vote_id, acct), ballot2.clone());

        // Cipher is inserted into Ciphers
        assert_eq!(
            OffchainModule::ciphers(topic_id.clone()),
            vec![cipher.clone(), cipher]
        );
    });
}

#[test]
fn test_offchain_signed_tx_encoded() {
    let (mut t, pool_state, _) = ExternalityBuilder::build();

    t.execute_with(|| {
        // Setup
        let (params, _, pk) = Helper::setup_sm_system();
        let q = &params.q();

        // Setup Vote
        let (vote_id, topic_id) = setup_vote(params.into());
        setup_public_key(vote_id.clone(), pk.clone().into());

        let num: u64 = 32;
        let big: BigUint = BigUint::from(num);
        let r = OffchainModule::get_random_biguint_less_than(q).unwrap();

        // use additive homomorphic encoding for message i.e. g^m
        let cipher: Cipher = ElGamal::encrypt_encode(&big, &r, &pk).into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher)];
        let ballot: Ballot = Ballot { answers };

        // Test
        OffchainModule::offchain_signed_tx(num, vote_id.clone(), topic_id).unwrap();

        // Verify
        let tx = pool_state.write().transactions.pop().unwrap();
        assert!(pool_state.read().transactions.is_empty());
        let tx = TestExtrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature.unwrap().0, 0);
        assert_eq!(tx.call, Call::cast_ballot(vote_id, ballot.clone()));
    });
}

#[test]
fn test_get_random_bytes() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let size: usize = 32;
        let random = OffchainModule::get_random_bytes(size).unwrap();
        assert_eq!(random.len(), size);
    });
}

#[test]
fn test_get_random_number_less_than() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let upper_bound: BigUint = BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
        let random = OffchainModule::get_random_biguint_less_than(&upper_bound).unwrap();
        assert!(random < upper_bound);
    });
}

#[test]
fn test_get_random_number_less_than_should_panic_number_is_zero() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let upper_bound: BigUint = BigUint::parse_bytes(b"0", 10).unwrap();
        OffchainModule::get_random_biguint_less_than(&upper_bound).expect_err(
            "The returned value should be: '<Error<T>>::RandomnessUpperBoundZeroError'",
        );
    });
}

#[test]
fn test_get_random_numbers_less_than() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let upper_bound: BigUint = BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
        let randoms: Vec<BigUint> =
            OffchainModule::get_random_biguints_less_than(&upper_bound, 10).unwrap();
        assert_eq!(randoms.len(), 10);
        let zero = BigUint::zero();
        for random in randoms.iter() {
            assert!(random < &upper_bound);
            assert!(random > &zero);
        }
    });
}

#[test]
fn test_get_random_numbers_less_than_should_panic_number_is_zero() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let upper_bound: BigUint = BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
        OffchainModule::get_random_biguints_less_than(&upper_bound, 0).expect_err(
            "The returned value should be: '<Error<T>>::RandomnessUpperBoundZeroError'",
        );
    });
}

#[test]
fn test_get_random_bigunint_range() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: BigUint = BigUint::parse_bytes(b"0", 10).unwrap();
        let upper: BigUint = BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
        let value = OffchainModule::get_random_bigunint_range(&lower, &upper).unwrap();

        assert!(value < upper);
        assert!(lower < value);
    });
}

#[test]
fn test_get_random_bigunint_range_upper_is_zero() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: BigUint = BigUint::parse_bytes(b"0", 10).unwrap();
        let upper: BigUint = BigUint::parse_bytes(b"0", 10).unwrap();
        OffchainModule::get_random_bigunint_range(&lower, &upper)
            .expect_err("The returned value should be: '<Error<T>>::RandomRangeError'");
    });
}

#[test]
fn test_get_random_bigunint_range_upper_is_not_larger_than_lower() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: BigUint = BigUint::parse_bytes(b"5", 10).unwrap();
        let upper: BigUint = BigUint::parse_bytes(b"5", 10).unwrap();
        OffchainModule::get_random_bigunint_range(&lower, &upper)
            .expect_err("The returned value should be: '<Error<T>>::RandomRangeError'");
    });
}

#[test]
fn test_get_random_range() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: usize = 0;
        let upper: usize = 100;
        let value = OffchainModule::get_random_range(lower, upper).unwrap();

        assert!(value < upper);
        assert!(lower < value);
    });
}

#[test]
fn test_get_random_range_upper_is_zero_error() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: usize = 0;
        let upper: usize = 0;
        OffchainModule::get_random_range(lower, upper)
            .expect_err("The returned value should be: '<Error<T>>::RandomRangeError'");
    });
}

#[test]
fn test_get_random_range_upper_is_not_larger_than_lower_error() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: usize = 5;
        let upper: usize = 5;
        OffchainModule::get_random_range(lower, upper)
            .expect_err("The returned value should be: '<Error<T>>::RandomRangeError'");
    });
}

#[test]
fn test_generate_permutation_size_zero_error() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let size = 0;
        OffchainModule::generate_permutation(size)
            .expect_err("The returned value should be: '<Error<T>>::PermutationSizeZeroError'");
    });
}

#[test]
fn test_should_generate_a_permutation_size_three() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let size = 3;
        let permutation = OffchainModule::generate_permutation(size).unwrap();

        // check that the permutation has the expected size
        assert!(permutation.len() == (size as usize));

        // check that 0, 1, 2 occur at least once each
        assert!(permutation.iter().any(|&value| value == 0));
        assert!(permutation.iter().any(|&value| value == 1));
        assert!(permutation.iter().any(|&value| value == 2));
    });
}

#[test]
fn test_fetch_ballots_size_zero() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let topic_id = "Moritz for President?".as_bytes().to_vec();
        // Read pallet storage (i.e. the submitted ballots)
        // and assert an expected result.
        let ciphers_from_chain: Vec<Cipher> = OffchainModule::ciphers(topic_id);
        assert!(ciphers_from_chain.len() == 0);
    });
}

#[test]
fn store_small_dummy_vote_works_encoded() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup Vote
        let (params, sk, pk) = Helper::setup_sm_system();
        let (vote_id, topic_id) = setup_vote(params.into());

        let message = BigUint::from(1u32);
        let random = BigUint::from(7u32);

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let big_cipher: BigCipher = ElGamal::encrypt_encode(&message, &random, &pk);

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let cipher: Cipher = big_cipher.clone().into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher.clone())];
        let ballot: Ballot = Ballot { answers };

        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        let vote_submission_result = OffchainModule::cast_ballot(voter, vote_id, ballot);
        assert_ok!(vote_submission_result);

        // fetch the submitted ballot
        let ciphers_from_chain: Vec<Cipher> = OffchainModule::ciphers(topic_id);
        assert!(ciphers_from_chain.len() > 0);

        let cipher_from_chain: Cipher = ciphers_from_chain[0].clone();
        assert_eq!(cipher, cipher_from_chain);

        // transform the Ballot -> BigCipher
        let big_cipher_from_chain: BigCipher = cipher_from_chain.into();
        assert_eq!(big_cipher, big_cipher_from_chain);

        let decrypted_vote = ElGamal::decrypt_decode(&big_cipher_from_chain, &sk);
        assert_eq!(message, decrypted_vote);
    });
}

#[test]
fn store_small_dummy_vote_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup Vote
        let (params, sk, pk) = Helper::setup_sm_system();
        let (vote_id, topic_id) = setup_vote(params.into());

        let message = BigUint::from(1u32);
        let random = BigUint::from(7u32);

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let big_cipher: BigCipher = ElGamal::encrypt(&message, &random, &pk);

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let cipher: Cipher = big_cipher.clone().into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher.clone())];
        let ballot: Ballot = Ballot { answers };

        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        let vote_submission_result = OffchainModule::cast_ballot(voter, vote_id, ballot);
        assert_ok!(vote_submission_result);

        // fetch the submitted ballot
        let ciphers_from_chain: Vec<Cipher> = OffchainModule::ciphers(topic_id);
        assert!(ciphers_from_chain.len() > 0);

        let cipher_from_chain: Cipher = ciphers_from_chain[0].clone();
        assert_eq!(cipher, cipher_from_chain);

        // transform the Ballot -> BigCipher
        let big_cipher_from_chain: BigCipher = cipher_from_chain.into();
        assert_eq!(big_cipher, big_cipher_from_chain);

        let decrypted_vote = ElGamal::decrypt(&big_cipher_from_chain, &sk);
        assert_eq!(message, decrypted_vote);
    });
}

#[test]
fn store_real_size_vote_works_encoded() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup
        let (params, sk, pk) = Helper::setup_md_system();
        let (vote_id, topic_id) = setup_vote(params.into());

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let message = BigUint::from(1u32);
        let random = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
        let big_cipher: BigCipher = ElGamal::encrypt_encode(&message, &random, &pk);

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let cipher: Cipher = big_cipher.clone().into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher.clone())];
        let ballot: Ballot = Ballot { answers };

        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        let vote_submission_result = OffchainModule::cast_ballot(voter, vote_id, ballot);
        assert_ok!(vote_submission_result);

        // fetch the submitted ballot
        let ciphers_from_chain: Vec<Cipher> = OffchainModule::ciphers(topic_id);
        assert!(ciphers_from_chain.len() > 0);

        let cipher_from_chain: Cipher = ciphers_from_chain[0].clone();
        assert_eq!(cipher, cipher_from_chain);

        // transform the Ballot -> BigCipher
        let big_cipher_from_chain: BigCipher = cipher_from_chain.into();
        assert_eq!(big_cipher, big_cipher_from_chain);

        let decrypted_vote = ElGamal::decrypt_decode(&big_cipher_from_chain, &sk);
        assert_eq!(message, decrypted_vote);
    });
}

#[test]
fn store_real_size_vote_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup
        let (params, sk, pk) = Helper::setup_md_system();
        let (vote_id, topic_id) = setup_vote(params.into());

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let message = BigUint::from(1u32);
        let random = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
        let big_cipher: BigCipher = ElGamal::encrypt(&message, &random, &pk);

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let cipher: Cipher = big_cipher.clone().into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher.clone())];
        let ballot: Ballot = Ballot { answers };

        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        let vote_submission_result = OffchainModule::cast_ballot(voter, vote_id, ballot);
        assert_ok!(vote_submission_result);

        // fetch the submitted ballot
        let ciphers_from_chain: Vec<Cipher> = OffchainModule::ciphers(topic_id);
        assert!(ciphers_from_chain.len() > 0);

        let cipher_from_chain: Cipher = ciphers_from_chain[0].clone();
        assert_eq!(cipher, cipher_from_chain);

        // transform the Ballot -> BigCipher
        let big_cipher_from_chain: BigCipher = cipher_from_chain.into();
        assert_eq!(big_cipher, big_cipher_from_chain);

        let decrypted_vote = ElGamal::decrypt(&big_cipher_from_chain, &sk);
        assert_eq!(message, decrypted_vote);
    });
}

#[test]
fn test_shuffle_ciphers_encoded() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup
        let (params, sk, pk) = Helper::setup_md_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        setup_public_key(vote_id.clone(), pk.clone().into());

        // create the public key
        let messages = [
            BigUint::from(5u32),
            BigUint::from(10u32),
            BigUint::from(15u32),
        ];

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let randoms = [
            b"170141183460469231731687303715884",
            b"170141183460469231731687303700084",
            b"170141183400069231731687303700084",
        ];

        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        for index in 0..3 {
            let random = BigUint::parse_bytes(randoms[index], 10).unwrap();

            // transform the ballot into a from that the blockchain can handle
            // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
            let cipher: Cipher = ElGamal::encrypt_encode(&messages[index], &random, &pk).into();
            let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher)];
            let ballot: Ballot = Ballot { answers };

            let vote_submission_result =
                OffchainModule::cast_ballot(voter.clone(), vote_id.clone(), ballot);
            assert_ok!(vote_submission_result);
        }

        // shuffle the votes
        let shuffle_result = OffchainModule::shuffle_ciphers(&vote_id, &topic_id);
        let shuffled_big_ciphers: Vec<BigCipher> = shuffle_result.unwrap().0;
        assert!(shuffled_big_ciphers.len() == 3);

        // type conversion: BigCipher (BigUint) to Ballot (Vec<u8>)
        let shuffled_ciphers: Vec<Cipher> = Wrapper(shuffled_big_ciphers).into();

        // transform each ballot into a cipher, decrypt_decode it and finally collect the list of biguints
        let decrypted_votes = shuffled_ciphers
            .iter()
            .map(|b| ElGamal::decrypt_decode(&(b.clone().into()), &sk))
            .collect::<Vec<BigUint>>();

        // check that at least one value is 5, 10, 15
        assert!(decrypted_votes
            .iter()
            .any(|decrypted_vote| *decrypted_vote == messages[0]));
        assert!(decrypted_votes
            .iter()
            .any(|decrypted_vote| *decrypted_vote == messages[1]));
        assert!(decrypted_votes
            .iter()
            .any(|decrypted_vote| *decrypted_vote == messages[2]));
    });
}

#[test]
fn test_shuffle_ciphers() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup
        let (params, sk, pk) = Helper::setup_md_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        setup_public_key(vote_id.clone(), pk.clone().into());

        // create the public key
        let messages = [
            BigUint::from(5u32),
            BigUint::from(10u32),
            BigUint::from(15u32),
        ];

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let randoms = [
            b"170141183460469231731687303715884",
            b"170141183460469231731687303700084",
            b"170141183400069231731687303700084",
        ];

        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        for index in 0..3 {
            let random = BigUint::parse_bytes(randoms[index], 10).unwrap();

            // transform the ballot into a from that the blockchain can handle
            // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
            let cipher: Cipher = ElGamal::encrypt(&messages[index], &random, &pk).into();
            let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher)];
            let ballot: Ballot = Ballot { answers };

            let vote_submission_result =
                OffchainModule::cast_ballot(voter.clone(), vote_id.clone(), ballot);
            assert_ok!(vote_submission_result);
        }

        // shuffle the votes
        let shuffle_result = OffchainModule::shuffle_ciphers(&vote_id, &topic_id);
        let shuffled_big_ciphers: Vec<BigCipher> = shuffle_result.unwrap().0;
        assert!(shuffled_big_ciphers.len() == 3);

        // type conversion: BigCipher (BigUint) to Ballot (Vec<u8>)
        let shuffled_ciphers: Vec<Cipher> = Wrapper(shuffled_big_ciphers).into();

        // transform each ballot into a cipher, decrypt_decode it and finally collect the list of biguints
        let decrypted_votes = shuffled_ciphers
            .iter()
            .map(|b| ElGamal::decrypt(&(b.clone().into()), &sk))
            .collect::<Vec<BigUint>>();

        // check that at least one value is 5, 10, 15
        assert!(decrypted_votes
            .iter()
            .any(|decrypted_vote| *decrypted_vote == messages[0]));
        assert!(decrypted_votes
            .iter()
            .any(|decrypted_vote| *decrypted_vote == messages[1]));
        assert!(decrypted_votes
            .iter()
            .any(|decrypted_vote| *decrypted_vote == messages[2]));
    });
}

#[test]
fn test_shuffle_ciphers_pk_does_not_exist() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let topic_id = "Moritz for President?".as_bytes().to_vec();
        let vote_id = "20201212".as_bytes().to_vec();
        // try to shuffle the ballots -> public key doesn't exist yet
        OffchainModule::shuffle_ciphers(&vote_id, &topic_id)
            .expect_err("The returned value should be: 'Error::<T>::PublicKeyNotExistsError'");
    });
}

#[test]
fn test_shuffle_ciphers_no_ballots() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let topic_id = "Moritz for President?".as_bytes().to_vec();
        let vote_id = "20201212".as_bytes().to_vec();
        let (_, _, pk) = Helper::setup_sm_system();
        setup_public_key(vote_id.clone(), pk.clone().into());

        // try -> to shuffle the ballots (which don't exist)
        OffchainModule::shuffle_ciphers(&vote_id, &topic_id)
            .expect_err("The returned value should be: 'Error::<T>::ShuffleCiphersSizeZeroError'");
    });
}

#[test]
fn test_permute_vector() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let test_vec: Vec<BigUint> = vec![
            BigUint::from(5u32),
            BigUint::from(10u32),
            BigUint::from(15u32),
        ];
        let permutation: Vec<usize> = vec![2, 0, 1];

        let result = OffchainModule::permute_vector(test_vec.clone(), &permutation);
        assert_eq!(result[0], test_vec[2]);
        assert_eq!(result[1], test_vec[0]);
        assert_eq!(result[2], test_vec[1]);
    });
}

#[test]
fn test_shuffle_proof_small_system_encoded() {
    // good primes to use for testing
    // p: 202178360940839 -> q: 101089180470419
    // p: 4283 -> q: 2141
    // p: 59 -> q: 29
    // p: 47 -> q: 23
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, pk) = Helper::setup_sm_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, topic_id, pk, true);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_shuffle_proof_small_system() {
    // good primes to use for testing
    // p: 202178360940839 -> q: 101089180470419
    // p: 4283 -> q: 2141
    // p: 59 -> q: 29
    // p: 47 -> q: 23
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, pk) = Helper::setup_sm_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, topic_id, pk, false);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_shuffle_proof_tiny_system_encoded() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, pk) = Helper::setup_tiny_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, topic_id, pk, true);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_shuffle_proof_tiny_system() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, pk) = Helper::setup_tiny_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, topic_id, pk, false);
        assert!(is_proof_valid);
    });
}

#[test]
#[ignore = "will take over 30s to complete, run only when necessary"]
fn test_shuffle_proof_medium_system() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, pk) = Helper::setup_md_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, topic_id, pk, false);
        assert!(is_proof_valid);
    });
}

#[test]
#[ignore = "will take over 30s to complete, run only when necessary"]
fn test_shuffle_proof_large_system() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, pk) = Helper::setup_lg_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, topic_id, pk, false);
        assert!(is_proof_valid);
    });
}

#[test]
#[ignore = "will take over 60s to complete, run only when necessary"]
fn test_shuffle_proof_xl_system() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, pk) = Helper::setup_xl_system();
        let (vote_id, topic_id) = setup_vote(params.into());
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, topic_id, pk, false);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_set_vote_phase_not_a_voting_authority() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (_, _, pk) = Helper::setup_sm_system();

        // create fake vote_id
        let vote_id = "20201212".as_bytes().to_vec();

        // Setup Public Key
        setup_public_key(vote_id.clone(), pk.clone().into());

        // use a normal user (i.e. the default voter)
        // NOT a voting authority
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let who = Origin::signed(account);

        // try to change the vote phase
        assert_err!(
            OffchainModule::set_vote_phase(who, vote_id, VotePhase::Voting),
            Error::<TestRuntime>::NotAVotingAuthority
        )
    });
}

#[test]
fn test_set_vote_phase_vote_does_not_exist() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (_, _, pk) = Helper::setup_sm_system();

        // create fake vote_id
        let vote_id = "20201212".as_bytes().to_vec();

        // Setup Public Key
        setup_public_key(vote_id.clone(), pk.clone().into());

        // create the submitter (i.e. the voting_authority)
        // use Alice as VotingAuthority
        let who = get_voting_authority();

        // try to change the vote phase
        assert_err!(
            OffchainModule::set_vote_phase(who, vote_id, VotePhase::Voting),
            Error::<TestRuntime>::VoteDoesNotExist
        )
    });
}

#[test]
fn test_set_vote_phase() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (params, _, pk) = Helper::setup_sm_system();

        // Setup Vote
        let (vote_id, _) = setup_vote(params.into());

        // Setup Public Key
        setup_public_key(vote_id.clone(), pk.clone().into());

        // create the submitter (i.e. the voting_authority)
        // use Alice as VotingAuthority
        let who = get_voting_authority();

        // change the VotePhase to Voting
        assert_ok!(OffchainModule::set_vote_phase(
            who.clone(),
            vote_id.clone(),
            VotePhase::Voting
        ));
        assert_eq!(
            OffchainModule::votes(vote_id.clone()).phase,
            VotePhase::Voting
        );

        // change the VotePhase to Tallying
        assert_ok!(OffchainModule::set_vote_phase(
            who,
            vote_id.clone(),
            VotePhase::Tallying
        ));
        assert_eq!(OffchainModule::votes(vote_id).phase, VotePhase::Tallying);
    });
}

#[test]
fn test_store_public_key_share_fail_is_voting_authority() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup
        let (params, sk, pk) = Helper::setup_md_system();
        let (vote_id, _) = setup_vote(params.clone().into());

        // create the submitter (i.e. the voting_authority)
        // use Alice as VotingAuthority
        let who = get_voting_authority();

        // create public key share + proof
        let sealer_id = "Bob".as_bytes();
        let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
        let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, sealer_id);
        let pk_share = PublicKeyShare {
            proof: proof.into(),
            pk: pk.h.to_bytes_be(),
        };

        // submit the public key share
        assert_err!(
            OffchainModule::store_public_key_share(who, vote_id, pk_share.into()),
            Error::<TestRuntime>::IsVotingAuthority
        )
    });
}

#[test]
fn test_store_public_key_share_fail_no_sealers() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup
        let (params, sk, pk) = Helper::setup_md_system();
        let (vote_id, _) = setup_vote(params.clone().into());

        // use a normal user (i.e. the default voter)
        // NOT a voting authority
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let who = Origin::signed(account);
        let sealer_id = "Bob".as_bytes();

        // create public key share + proof
        let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
        let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, sealer_id);
        let pk_share = PublicKeyShare {
            proof: proof.into(),
            pk: pk.h.to_bytes_be(),
        };

        // submit the public key share
        assert_err!(
            OffchainModule::store_public_key_share(who, vote_id, pk_share.into()),
            Error::<TestRuntime>::NotASealer
        )
    });
}

#[test]
fn test_store_public_key_share() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup
        let (params, sk, pk) = Helper::setup_md_system();
        let (vote_id, _) = setup_vote(params.clone().into());

        // use sealer bob
        let (who, account_id, sealer_id) = get_sealer_bob();
        let (_, proof) = setup_sealer(&params, &sk, &pk, who, &vote_id, &sealer_id);

        // verify the public key share submission + proof verification
        let shares: Vec<PublicKeyShare> = OffchainModule::key_shares(vote_id.clone());
        assert_eq!(shares[0].pk, pk.h.to_bytes_be());
        assert_eq!(shares[0].proof.challenge, proof.challenge.to_bytes_be());
        assert_eq!(shares[0].proof.response, proof.response.to_bytes_be());

        let share_by_sealer: PublicKeyShare =
            OffchainModule::key_share_by_sealer((vote_id, account_id));
        assert_eq!(share_by_sealer.pk, pk.h.to_bytes_be());
        assert_eq!(
            share_by_sealer.proof.challenge,
            proof.challenge.to_bytes_be()
        );
        assert_eq!(share_by_sealer.proof.response, proof.response.to_bytes_be());
    });
}

#[test]
fn test_combine_public_key_shares_not_voting_authority() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create fake vote_id
        let vote_id = "20201212".as_bytes().to_vec();

        // Use sealer instead of voting authority
        let (bob, _, _) = get_sealer_bob();
        assert_err!(
            OffchainModule::combine_public_key_shares(bob, vote_id),
            Error::<TestRuntime>::NotAVotingAuthority
        );
    });
}

#[test]
fn test_combine_public_key_shares_vote_does_not_exist() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create fake vote_id
        let vote_id = "20201212".as_bytes().to_vec();

        // use authority but vote doesn't exist
        let who = get_voting_authority();
        assert_err!(
            OffchainModule::combine_public_key_shares(who, vote_id),
            Error::<TestRuntime>::VoteDoesNotExist
        );
    });
}

#[test]
fn test_combine_public_key_shares() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // Setup
        let (params, sk, pk) = Helper::setup_md_system();
        let (vote_id, _) = setup_vote(params.clone().into());

        // Use 1. Sealer: Bob
        let (bob, _, bob_sealer_id) = get_sealer_bob();
        let (bob_key, _) = setup_sealer(&params, &sk, &pk, bob, &vote_id, &bob_sealer_id);

        // Use 2. Sealer: Charlie
        let (charlie, _, charlie_sealer_id) = get_sealer_charlie();
        let (charlie_key, _) =
            setup_sealer(&params, &sk, &pk, charlie, &vote_id, &charlie_sealer_id);

        // combine the public key shares
        let voting_authority = get_voting_authority();
        assert_ok!(OffchainModule::combine_public_key_shares(
            voting_authority,
            vote_id.clone()
        ));

        // VERIFY
        // fetch the public key from the chain
        let pk = ElGamalPK {
            h: BigUint::from_bytes_be(&bob_key.pk)
                .modmul(&BigUint::from_bytes_be(&charlie_key.pk), &params.p),
            params: params.clone(),
        };
        let pk_from_chain: ElGamalPK = OffchainModule::public_key(vote_id).unwrap().into();
        assert_eq!(pk_from_chain, pk);
    });
}
