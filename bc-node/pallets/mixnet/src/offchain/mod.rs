mod send;

use crate::{
    helpers::{assertions::ensure_vote_exists, params::get_public_key},
    types::{
        Ballot, Cipher, ShuffleProof, ShuffleProofAsBytes, Topic, TopicId, Vote, VoteId,
        VotePhase, Wrapper,
    },
};
use crate::{
    Call, Ciphers, Error, Module, Sealers, Topics, Trait, VoteIds, Votes,
    VotingAuthorities,
};
use core::convert::TryInto;
use crypto::{
    encryption::ElGamal, types::Cipher as BigCipher, types::PublicKey as ElGamalPK,
};
use frame_support::{
    debug,
    storage::{StorageDoubleMap, StorageMap, StorageValue},
    traits::Get,
};
use frame_system::offchain::Signer;
use num_bigint::BigUint;
use send::send_signed;
use sp_std::{vec, vec::Vec};

impl<T: Trait> Module<T> {
    pub fn offchain_signed_tx(
        block_number: T::BlockNumber,
        vote_id: Vec<u8>,
        topic_id: Vec<u8>,
    ) -> Result<(), Error<T>> {
        ensure_vote_exists::<T>(&vote_id)?;

        // We retrieve a signer and check if it is valid.
        // ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
        let signer = Signer::<T, T::AuthorityId>::any_account();

        // translating the current block number to number and submit it on-chain
        let number: u64 = block_number.try_into().unwrap_or(0u64) as u64;

        // transform u64 to BigUint
        let number_as_biguint: BigUint = BigUint::from(number);

        // get public key
        let pk: ElGamalPK = get_public_key::<T>(&vote_id)?.into();
        let q = &pk.params.q();

        // get a random value < q
        let r = Self::get_random_biguint_less_than(q)?;

        // encrypt the current block number
        let cipher: Cipher = ElGamal::encrypt_encode(&number_as_biguint, &r, &pk).into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id, cipher)];
        let ballot: Ballot = Ballot { answers };

        return send_signed::<T>(
            signer,
            Call::cast_ballot(vote_id.clone(), ballot.clone()),
        );
    }

    pub fn do_work_in_offchain_worker(
        block_number: T::BlockNumber,
    ) -> Result<(), Error<T>> {
        if sp_io::offchain::is_validator() {
            debug::info!("hi there i'm a validator");

            let duration = T::BlockDuration::get();
            let zero: T::BlockNumber = T::BlockNumber::from(0u32);
            debug::info!("block duration: {:#?}", duration);

            let timestamp = sp_io::offchain::timestamp();
            debug::info!("timestamp: {:#?}", timestamp);

            let sealers: Vec<T::AccountId> = Sealers::<T>::get();
            debug::info!("sealers: {:#?}", sealers);

            let voting_authorities: Vec<T::AccountId> = VotingAuthorities::<T>::get();
            debug::info!("voting_authorities: {:#?}", voting_authorities);

            // shuffle votes + create a proof
            if duration > zero && block_number % duration == zero {
                debug::info!("boss move");
            }

            // check who's turn it is
            let n: T::BlockNumber = (sealers.len() as u32).into();
            let index = block_number % n;

            let test = TryInto::<u64>::try_into(index).ok();
            let index_as_u64 = test.expect("Type conversion failed!");
            let sealer: &T::AccountId = &sealers[index_as_u64 as usize];
            debug::info!("it is sealer {:#?} (index: {:#?})", sealer, index);

            // creat the shuffle
            let result_ = Self::offchain_shuffle_and_proof()?;

            // get the signer for the transaction
            let signer = Signer::<T, T::AuthorityId>::any_account();

            // call send + return its result
            return send_signed::<T>(signer, Call::test(true));
        }
        Ok(())
    }

    fn offchain_shuffle_and_proof() -> Result<(), Error<T>> {
        // get all vote_ids
        let vote_ids: Vec<VoteId> = VoteIds::get();

        for vote_id in vote_ids.iter() {
            debug::info!("vote_id: {:#?}", vote_id);

            // check vote state -> TALLYING
            let vote: Vote<T::AccountId> = Votes::<T>::get(&vote_id);
            let state: VotePhase = vote.phase;

            if state == VotePhase::Tallying {
                // get all topics
                let topics: Vec<Topic> = Topics::get(vote_id);

                // get public key
                let pk: ElGamalPK = get_public_key::<T>(&vote_id)?.into();

                // TODO: figure out a way on how to decide what the current number of shuffles is
                let current_nr_of_shuffles: u8 = 0;

                for (topic_id, _) in topics.iter() {
                    // get all encrypted votes (ciphers)
                    // for the topic with id: topic_id and the # of shuffles (current_nr_of_shuffles)
                    // TODO: implement a function to retrieve the most recent number of shuffles...
                    let ciphers: Vec<Cipher> =
                        Ciphers::get(&topic_id, current_nr_of_shuffles);

                    // type conversion: Cipher (Vec<u8>) to BigCipher (BigUint)
                    let encryptions: Vec<BigCipher> = Wrapper(ciphers).into();

                    // for each topic_id & vote_id
                    // shuffle the votes
                    let (shuffled_encryptions, re_encryption_randoms, permutation): (
                        Vec<BigCipher>,
                        Vec<BigUint>,
                        Vec<usize>,
                    ) = Self::shuffle_ciphers(vote_id, topic_id, current_nr_of_shuffles)?;

                    // generate the shuffle proof
                    let proof: ShuffleProof = Self::generate_shuffle_proof(
                        &topic_id,
                        encryptions,
                        shuffled_encryptions.clone(),
                        re_encryption_randoms,
                        &permutation,
                        &pk,
                    )?;

                    // type conversions
                    let shuffled_encryptions_as_bytes: Vec<Cipher> =
                        Wrapper(shuffled_encryptions).into();
                    let proof_as_bytes: ShuffleProofAsBytes = proof.into();

                    // get the signer for the transaction
                    let signer = Signer::<T, T::AuthorityId>::any_account();

                    // submit the shuffle proof and the shuffled ciphers
                    send_signed::<T>(
                        signer,
                        Call::submit_shuffle_proof(
                            vote_id.to_vec(),
                            topic_id.to_vec(),
                            proof_as_bytes,
                            shuffled_encryptions_as_bytes,
                            current_nr_of_shuffles,
                        ),
                    )?;
                }
            }
        }
        Ok(())
    }

    // TODO: implement shuffle_ciphers -> used by offchain worker
    // TODO: implement generate_shuffle_proof -> used by offchain worker
}

// TODO: implement creating a decrypted share + submitting it -> used by offchain worker
