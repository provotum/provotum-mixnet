use crate::*;
use crate::{mock::*, types::Wrapper};
use crate::{types::Ballot, types::PublicKey};
use codec::Decode;
use crypto::{
    encryption::ElGamal, helper::Helper, types::Cipher, types::PublicKey as ElGamalPK,
};
use frame_support::assert_ok;
use frame_system as system;
use num_traits::Zero;

#[test]
fn test_submit_number_signed_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // call submit_number_signed
        let num = 32;
        let acct: <TestRuntime as system::Trait>::AccountId = Default::default();
        assert_ok!(OffchainModule::submit_number_signed(
            Origin::signed(acct),
            num
        ));
        // A number is inserted to <Numbers> vec
        assert_eq!(<Numbers>::get(), vec![num]);
        // An event is emitted
        assert!(System::events().iter().any(|er| er.event
            == TestEvent::pallet_mixer(RawEvent::NewNumber(Some(acct), num))));

        // Insert another number
        let num2 = num * 2;
        assert_ok!(OffchainModule::submit_number_signed(
            Origin::signed(acct),
            num2
        ));
        // A number is inserted to <Numbers> vec
        assert_eq!(<Numbers>::get(), vec![num, num2]);
    });
}

#[test]
fn test_offchain_signed_tx() {
    let (mut t, pool_state, _) = ExternalityBuilder::build();

    t.execute_with(|| {
        // Setup
        let num = 32;
        OffchainModule::offchain_signed_tx(num).unwrap();

        // Verify
        let tx = pool_state.write().transactions.pop().unwrap();
        assert!(pool_state.read().transactions.is_empty());
        let tx = TestExtrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature.unwrap().0, 0);
        assert_eq!(tx.call, Call::submit_number_signed(num));
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
        let upper_bound: BigUint =
            BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
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
        let upper_bound: BigUint =
            BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
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
        let upper_bound: BigUint =
            BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
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
        let upper: BigUint =
            BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
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
        OffchainModule::generate_permutation(size).expect_err(
            "The returned value should be: '<Error<T>>::PermutationSizeZeroError'",
        );
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
        // Read pallet storage (i.e. the submitted ballots)
        // and assert an expected result.
        let votes_from_chain: Vec<Ballot> = OffchainModule::ballots();
        assert!(votes_from_chain.len() == 0);
    });
}

#[test]
fn store_small_dummy_vote() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (_, sk, pk) = Helper::setup_system(b"23", b"7");
        let message = BigUint::from(1u32);
        let random = BigUint::from(7u32);

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let cipher: Cipher = ElGamal::encrypt(&message, &random, &pk);

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let encrypted_vote: Ballot = cipher.clone().into();

        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        let vote_submission_result =
            OffchainModule::cast_ballot(voter, encrypted_vote.clone());
        assert_ok!(vote_submission_result);

        // fetch the submitted ballot
        let votes_from_chain: Vec<Ballot> = OffchainModule::ballots();
        assert!(votes_from_chain.len() > 0);

        let vote_from_chain: Ballot = votes_from_chain[0].clone();
        assert_eq!(encrypted_vote, vote_from_chain);

        // transform the Ballot -> Cipher
        let cipher_from_chain: Cipher = vote_from_chain.into();
        assert_eq!(cipher, cipher_from_chain);

        let decrypted_vote = ElGamal::decrypt(&cipher_from_chain, &sk);
        assert_eq!(message, decrypted_vote);
    });
}

#[test]
fn store_real_size_vote() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let (_, sk, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
        
        b"1701411834604692317316873037");
        let message = BigUint::from(1u32);
        let random = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let cipher: Cipher = ElGamal::encrypt(&message, &random, &pk);

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let encrypted_vote: Ballot = cipher.clone().into();
        
        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        let vote_submission_result = OffchainModule::cast_ballot(voter, encrypted_vote.clone());
        assert_ok!(vote_submission_result);

        // fetch the submitted ballot
        let votes_from_chain: Vec<Ballot> = OffchainModule::ballots();
        assert!(votes_from_chain.len() > 0);

        let vote_from_chain: Ballot = votes_from_chain[0].clone();
        assert_eq!(encrypted_vote, vote_from_chain);
        
        // transform the Ballot -> Cipher
        let cipher_from_chain: Cipher = vote_from_chain.into();
        assert_eq!(cipher, cipher_from_chain);

        let decrypted_vote = ElGamal::decrypt(&cipher_from_chain, &sk);
        assert_eq!(message, decrypted_vote);
    });
}

#[test]
fn test_store_public_key() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create the submitter (i.e. the public key submitter)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let who = Origin::signed(account);

        // create the public key        
        let (_, _, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
        
        b"1701411834604692317316873037");

        // store created public key and public parameters
        let public_key_storage = OffchainModule::store_public_key(who, pk.clone().into());
        assert_ok!(public_key_storage);

        // fetch the public key from the chain
        let pk_from_chain: ElGamalPK = OffchainModule::public_key().unwrap().into();
        assert_eq!(pk_from_chain, pk);
    });
}

#[test]
fn test_fetch_public_key_does_not_exist() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // fetch the public key from the chain which doesn't exist
        let pk_from_chain: Option<PublicKey> = OffchainModule::public_key();
        assert_eq!(pk_from_chain, None);
    });
}

#[test]
fn test_shuffle_ballots() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create the submitter (i.e. the public key submitter)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let who = Origin::signed(account);

        // create the public key    
        let (_, sk, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457",        
        b"1701411834604692317316873037");
        let messages = [BigUint::from(5u32), BigUint::from(10u32), BigUint::from(15u32)];

        // store created public key and public parameters
        let public_key_storage = OffchainModule::store_public_key(who, pk.clone().into());
        assert_ok!(public_key_storage);
        
        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let randoms = [
            b"170141183460469231731687303715884", b"170141183460469231731687303700084", b"170141183400069231731687303700084"
        ];

        // create the voter (i.e. the transaction signer)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let voter = Origin::signed(account);

        for index in 0..3 {
            let random = BigUint::parse_bytes(randoms[index], 10).unwrap();

            // transform the ballot into a from that the blockchain can handle
            // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
            let encrypted_vote: Ballot = ElGamal::encrypt(&messages[index], &random, &pk).into();
    
            let vote_submission_result = OffchainModule::cast_ballot(voter.clone(), encrypted_vote.clone());
            assert_ok!(vote_submission_result);
        }
        
        // shuffle the votes
        let shuffle_result = OffchainModule::shuffle_ballots();
        let shuffled_ciphers: Vec<Cipher> = shuffle_result.unwrap().0;
        assert!(shuffled_ciphers.len() == 3);

        // type conversion: Cipher (BigUint) to Ballot (Vec<u8>)
        let shuffled_ballots: Vec<Ballot> = Wrapper(shuffled_ciphers).into();

        // transform each ballot into a cipher, decrypt it and finally collect the list of biguints
        let decrypted_votes = shuffled_ballots.iter().map(|b| ElGamal::decrypt(&(b.clone().into()), &sk)).collect::<Vec<BigUint>>();

        // check that at least one value is 5, 10, 15
        assert!(decrypted_votes.iter().any(|decrypted_vote| *decrypted_vote == messages[0]));        
        assert!(decrypted_votes.iter().any(|decrypted_vote| *decrypted_vote == messages[1]));        
        assert!(decrypted_votes.iter().any(|decrypted_vote| *decrypted_vote == messages[2]));
    });
}

#[test]
fn test_shuffle_ballots_pk_does_not_exist() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // try to shuffle the ballots -> public key doesn't exist yet
        OffchainModule::shuffle_ballots().expect_err(
            "The returned value should be: 'Error::<T>::PublicKeyNotExistsError'",
        );
    });
}

#[test]
fn test_shuffle_ballots_no_ballots() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // create the submitter (i.e. the public key submitter)
        let account: <TestRuntime as system::Trait>::AccountId = Default::default();
        let who = Origin::signed(account);

        // create the public key
        let (_, _, pk) = Helper::setup_system(b"31", b"3");

        // store created public key and public parameters
        let public_key_storage = OffchainModule::store_public_key(who, pk.clone().into());
        assert_ok!(public_key_storage);

        // try -> to shuffle the ballots (which don't exist)
        OffchainModule::shuffle_ballots().expect_err(
            "The returned value should be: 'Error::<T>::ShuffleBallotsSizeZeroError'",
        );
    });
}

#[test]
fn test_shuffle_proof_vote_id1_p59_x4() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let vote_id = 1usize;
        let (_, _, pk) = Helper::setup_system(b"59", b"4");
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, pk);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_shuffle_proof_vote_id1_p59_x0() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let vote_id = 1usize;
        let (_, _, pk) = Helper::setup_system(b"59", b"0");
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, pk);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_shuffle_proof_vote_id1_p59_x28() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let vote_id = 1usize;
        let (_, _, pk) = Helper::setup_system(b"59", b"28");
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, pk);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_shuffle_proof_vote_id1_p59_x1() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let vote_id = 1usize;
        let (_, _, pk) = Helper::setup_system(b"59", b"1");
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, pk);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_shuffle_proof_vote_id25_p4283_x1500() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let vote_id = 25usize;
        let (_, _, pk) = Helper::setup_system(b"4283", b"1500");
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, pk);
        assert!(is_proof_valid);
    });
}

#[test]
fn test_shuffle_proof_vote_id231_p202178360940839_x35() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // good primes to use for testing
        // p: 202178360940839 -> q: 101089180470419
        // p: 4283 -> q: 2141
        // p: 59 -> q: 29
        // p: 47 -> q: 23
        let vote_id = 231usize;
        let (_, _, pk) = Helper::setup_system(b"202178360940839", b"35");
        let is_p_prime = OffchainModule::is_prime(&pk.params.p, 10).unwrap();
        assert!(is_p_prime);
        let is_q_prime = OffchainModule::is_prime(&pk.params.q(), 10).unwrap();
        assert!(is_q_prime);

        let is_proof_valid = shuffle_proof_test(vote_id, pk);
        assert!(is_proof_valid);
    });
}

fn shuffle_proof_test(vote_id: usize, pk: ElGamalPK) -> bool {
    let messages = [
        BigUint::from(0u32),
        BigUint::from(1u32),
        BigUint::from(2u32),
    ];

    // create the submitter (i.e. the public key submitter)
    let account: <TestRuntime as system::Trait>::AccountId = Default::default();
    let who = Origin::signed(account);

    // store created public key and public parameters
    let public_key_storage = OffchainModule::store_public_key(who, pk.clone().into());
    assert_ok!(public_key_storage);

    // encrypt the message -> encrypted message
    // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
    let randoms = [b"7", b"6", b"5"];

    // create the voter (i.e. the transaction signer)
    let account: <TestRuntime as system::Trait>::AccountId = Default::default();
    let voter = Origin::signed(account);

    for index in 0..3 {
        let random = BigUint::parse_bytes(randoms[index], 10).unwrap();

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let encrypted_vote: Ballot =
            ElGamal::encrypt(&messages[index], &random, &pk).into();

        let vote_submission_result =
            OffchainModule::cast_ballot(voter.clone(), encrypted_vote.clone());
        assert_ok!(vote_submission_result);
    }

    // get the encrypted votes
    let votes_from_chain: Vec<Cipher> = Wrapper(OffchainModule::ballots()).into();
    assert!(votes_from_chain.len() > 0);

    // shuffle the votes
    let shuffle_result = OffchainModule::shuffle_ballots();
    let shuffled: (Vec<Cipher>, Vec<BigUint>, Vec<usize>) = shuffle_result.unwrap();
    let shuffled_ciphers = shuffled.0;
    let re_encryption_randoms = shuffled.1;
    let permutation = &shuffled.2;

    // TEST
    // GENERATE PROOF
    let result = OffchainModule::generate_shuffle_proof(
        vote_id,
        votes_from_chain.clone(),
        shuffled_ciphers.clone(),
        re_encryption_randoms,
        permutation,
        &pk,
    );
    let proof: (
        BigUint, // challenge
        (
            BigUint,      // s1
            BigUint,      // s2
            BigUint,      // s3
            BigUint,      // s4
            Vec<BigUint>, // vec_s_hat
            Vec<BigUint>, // vec_s_tilde
        ),
        Vec<BigUint>, // permutation_commitments
        Vec<BigUint>, // permutation_chain_commitments
    ) = result.unwrap();

    // VERIFY PROOF
    let verification = OffchainModule::verify_shuffle_proof(
        vote_id,
        proof,
        votes_from_chain,
        shuffled_ciphers,
        &pk,
    );
    let is_proof_valid = verification.unwrap();
    is_proof_valid
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
