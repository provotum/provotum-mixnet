use crate::types::Ballot;
use crate::{mock::*, Error};
use crypto::elgamal::encryption::ElGamal;
use crypto::elgamal::types::{Cipher};
use crypto::elgamal::helper::Helper;
use frame_support::{assert_noop, assert_ok};
use num_bigint::BigUint;


#[test]
fn it_works_for_default_value() {
    new_test_ext().execute_with(|| {
        // Dispatch a signed extrinsic.
        assert_ok!(MixnetModule::do_something(Origin::signed(1), 42));
        // Read pallet storage and assert an expected result.
        assert_eq!(MixnetModule::something(), Some(42));
    });
}

#[test]
fn correct_error_for_none_value() {
    new_test_ext().execute_with(|| {
        // Ensure the expected error is thrown when no value is present.
        assert_noop!(
            MixnetModule::cause_error(Origin::signed(1)),
            Error::<Test>::NoneValue
        );
    });
}

#[test]
fn store_small_dummy_vote() {
    new_test_ext().execute_with(|| {
        let (_, sk, pk) = Helper::setup_system(b"23", b"2", b"7");
        let message = BigUint::from(1u32);
        let random = BigUint::from(7u32);

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let cipher: Cipher = ElGamal::encrypt(&message, &random, &pk);

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let encrypted_vote: Ballot = cipher.clone().into();
        let voter = Origin::signed(1);

        let vote_submission_result = MixnetModule::cast_ballot(voter, encrypted_vote.clone());
        assert_ok!(vote_submission_result);

        // fetch the submitted ballot
        let votes_from_chain: Vec<Ballot> = MixnetModule::ballots();
        assert!(votes_from_chain.len() > 0);

        let vote_from_chain: Ballot = votes_from_chain[0].clone();
        assert_eq!(encrypted_vote, vote_from_chain);
        println!("Encrypted Ballot: {:?}", vote_from_chain);
        
        // transform the Ballot -> Cipher
        let cipher_from_chain: Cipher = vote_from_chain.into();
        assert_eq!(cipher, cipher_from_chain);

        let decrypted_vote = ElGamal::decrypt(&cipher_from_chain, &sk);
        assert_eq!(message, decrypted_vote);
    })
}

#[test]
fn store_real_size_vote() {
    new_test_ext().execute_with(|| {
        let (_, sk, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
        b"2", 
        b"1701411834604692317316873037");
        let message = BigUint::from(1u32);
        let random = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();

        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let cipher: Cipher = ElGamal::encrypt(&message, &random, &pk);

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let encrypted_vote: Ballot = cipher.clone().into();
        let voter = Origin::signed(1);

        let vote_submission_result = MixnetModule::cast_ballot(voter, encrypted_vote.clone());
        assert_ok!(vote_submission_result);

        // fetch the submitted ballot
        let votes_from_chain: Vec<Ballot> = MixnetModule::ballots();
        assert!(votes_from_chain.len() > 0);

        let vote_from_chain: Ballot = votes_from_chain[0].clone();
        assert_eq!(encrypted_vote, vote_from_chain);
        
        // transform the Ballot -> Cipher
        let cipher_from_chain: Cipher = vote_from_chain.into();
        assert_eq!(cipher, cipher_from_chain);

        let decrypted_vote = ElGamal::decrypt(&cipher_from_chain, &sk);
        assert_eq!(message, decrypted_vote);
    })
}

#[test]
fn shuffle_votes() {
    new_test_ext().execute_with(|| {
        let (_, sk, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
        b"2", 
        b"1701411834604692317316873037");
        let messages = [BigUint::from(5u32), BigUint::from(10u32), BigUint::from(15u32)];
        
        // encrypt the message -> encrypted message
        // cipher = the crypto crate version of a ballot { a: BigUint, b: BigUint }
        let randoms = [b"170141183460469231731687303715884", b"170141183460469231731687303700084", b"170141183400069231731687303700084"];

        for index in 0..3 {
            let random = BigUint::parse_bytes(randoms[index], 10).unwrap();
            let cipher: Cipher = ElGamal::encrypt(&messages[index], &random, &pk);
    
            // transform the ballot into a from that the blockchain can handle
            // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
            let encrypted_vote: Ballot = cipher.clone().into();
            let voter = Origin::signed(1);
    
            let vote_submission_result = MixnetModule::cast_ballot(voter, encrypted_vote.clone());
            assert_ok!(vote_submission_result);

        }
        
        // shuffle the votes
        let voter = Origin::signed(1);
        let shuffle_result = MixnetModule::trigger_shuffle(voter, pk.into());
        assert_ok!(shuffle_result);

        // fetch the submitted ballot
        let votes_from_chain: Vec<Ballot> = MixnetModule::ballots();
        assert!(votes_from_chain.len() == 3);

        let mut decrypted_votes = vec![];

        for vote_from_chain in votes_from_chain {            
            // transform the Ballot -> Cipher          
            let cipher_from_chain: Cipher = vote_from_chain.into();    
            let decrypted_vote = ElGamal::decrypt(&cipher_from_chain, &sk);
            decrypted_votes.push(decrypted_vote);
        }

        // check that at least one value is 5, 10, 15
        assert!(decrypted_votes.iter().any(|decrypted_vote| *decrypted_vote == messages[0]));        
        assert!(decrypted_votes.iter().any(|decrypted_vote| *decrypted_vote == messages[1]));        
        assert!(decrypted_votes.iter().any(|decrypted_vote| *decrypted_vote == messages[2]));
    })
}
