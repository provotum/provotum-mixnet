mod send;

use crate::{
    helpers::{assertions::ensure_vote_exists, params::get_public_key},
    types::{
        Ballot, Cipher, PublicKey as SubstratePK, ShufflePayload, ShuffleProof,
        ShuffleProofAsBytes, Topic, TopicId, Vote, VoteId, VotePhase, Wrapper,
    },
};
use crate::{Call, Ciphers, Error, Module, Sealers, Topics, Trait, VoteIds, Votes};
use core::convert::TryInto;
use crypto::{
    encryption::ElGamal, types::Cipher as BigCipher, types::PublicKey as ElGamalPK,
};
use frame_support::{
    debug,
    storage::{StorageDoubleMap, StorageMap, StorageValue},
    traits::Get,
};
use frame_system::offchain::{SendSignedTransaction, Signer};
use num_bigint::BigUint;
use send::send_signed;
use sp_runtime::offchain::storage::StorageValueRef;
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

    pub fn offchain_shuffle_and_proof(
        block_number: T::BlockNumber,
    ) -> Result<(), Error<T>> {
        // if the offchain worker is not a validator, we don't shuffle the votes
        if !sp_io::offchain::is_validator() {
            return Ok(());
        }

        // Only attempt to shuffle votes
        // every #BlockDuration of blocks
        let duration = T::BlockDuration::get();
        let zero: T::BlockNumber = T::BlockNumber::from(0u32);
        if block_number % duration != zero {
            return Ok(());
        }

        // get all vote_ids
        let vote_ids: Vec<VoteId> = VoteIds::get();
        debug::info!("vote_ids: {:?}", vote_ids);

        for vote_id in vote_ids.iter() {
            // check vote state -> TALLYING
            let vote: Vote<T::AccountId> = Votes::<T>::get(&vote_id);
            let state: VotePhase = vote.phase;

            // early return if the vote is not in
            if state != VotePhase::Tallying {
                continue;
            }

            debug::info!("vote_id: {:?}, state: VotePhase::Tallying", vote_id);

            // get all topics
            let topics: Vec<Topic> = Topics::get(vote_id);

            // get public key
            let pk: SubstratePK = get_public_key::<T>(&vote_id)?;
            let pk: ElGamalPK = pk.into();

            // TODO: figure out a way on how to decide what the current number of shuffles is
            let current_nr_of_shuffles: u8 = 0;

            for (topic_id, _) in topics.iter() {
                // get all encrypted votes (ciphers)
                // for the topic with id: topic_id and the # of shuffles (current_nr_of_shuffles)
                // TODO: implement a function to retrieve the most recent number of shuffles...
                debug::info!("topic_id: {:?}", topic_id);
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
                ) = Self::shuffle_ciphers(pk.clone(), encryptions.clone())?;

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

                // check who's turn it is
                let sealers: Vec<T::AccountId> = Sealers::<T>::get();
                let nr_sealer: u64 = sealers.len() as u64;
                let (current_sealer, index) =
                    Self::get_current_sealer(block_number, sealers);

                // submit the shuffle proof and the shuffled ciphers
                let result = signer.send_signed_transaction(|_acct| {
                    let local_address = &_acct.id;
                    let payload = ShufflePayload {
                        ciphers: shuffled_encryptions_as_bytes.clone(),
                        proof: proof_as_bytes.clone(),
                        iteration: current_nr_of_shuffles,
                    };

                    // experiment with storing shuffle information
                    let result = Self::get_shuffle_start_position(index, nr_sealer, 2u64);
                    if result.is_ok() && current_sealer.eq(local_address) {
                        let start_position = result.unwrap();
                        debug::info!(
                            "start position for sealer: {:?} is: {:?}",
                            current_sealer,
                            start_position
                        );

                        Call::submit_shuffled_votes_and_proof(
                            vote_id.to_vec(),
                            topic_id.to_vec(),
                            payload,
                        )
                    } else {
                        Call::do_nothing_when_its_not_your_turn()
                    }
                });

                // handle the response
                if let Some((acc, res)) = result {
                    // display error if the signed tx fails.
                    if res.is_err() {
                        debug::error!(
                            "failure in offchain tx, acc: {:?}, res: {:?}",
                            acc.id,
                            res
                        );
                    }
                    // Transaction is sent successfully
                    if current_sealer.eq(&acc.id) {
                        debug::info!(
                            "votes shuffled in offchain worker -> vote_id: {:?}",
                            vote_id
                        );
                    }
                } else {
                    // The case of `None`: no account is available for sending
                    debug::error!("No local account available");
                    return Err(<Error<T>>::NoLocalAcctForSigning);
                }
            }
        }
        Ok(())
    }

    fn get_shuffle_start_position(
        sealer_index: u64,
        nr_sealers: u64,
        batch_size: u64,
    ) -> Result<u64, Error<T>> {
        let store =
            StorageValueRef::persistent(b"pallet_mixnet_ocw::shuffle::current_round");
        let result = store.mutate(|round: Option<Option<u64>>| {
            // We match on the value decoded from the storage. The first `Option` indicates if the value was present in the storage at all, the second (inner) `Option` indicates if the value was succesfuly decoded to expected type (`u64`).
            match round {
                // If we already have a value in storage, we increment it by 1.
                Some(Some(value)) => {
                    debug::info!("previous round read: {:?}", value);
                    Ok(value + 1)
                }

                Some(None) => {
                    debug::info!("error could not persist round value.");
                    Err(())
                }

                // Initially, we start with round 0.
                _ => {
                    debug::info!("round init: 0");
                    Ok(0)
                }
            }
        });

        match result {
            Ok(Ok(round_number)) => {
                debug::info!("current round number: {:?}", round_number);
                let start_position =
                    Self::get_batch(sealer_index, round_number, nr_sealers, batch_size);
                Ok(start_position)
            }
            _ => {
                debug::error!("error computing shuffle start position: {:?}", result);
                Err(<Error<T>>::CouldNotComputeShuffleStartPosition)
            }
        }
    }

    /// computes the total number of rounds required to shuffle all ciphers
    /// round_size = # of sealers * batch_size
    /// total # of rounds = # of ciphers / round_size
    fn get_total_rounds(nr_ciphers: u64, nr_sealers: u64, batch_size: u64) -> u64 {
        let round_size = nr_sealers * batch_size;
        nr_ciphers / round_size
    }

    /// computes the shuffle batch starting point for each sealer
    /// round_size = # of sealers * batch_size
    /// start_point = sealer_index * batch_size + round_size * round
    fn get_batch(index: u64, round: u64, nr_sealers: u64, batch_size: u64) -> u64 {
        let round_size = nr_sealers * batch_size;
        let batch_position = index * batch_size;
        let round_position = round_size * round;
        batch_position + round_position
    }

    /// retrieves the current sealer, depends on the block number
    fn get_current_sealer(
        block_number: T::BlockNumber,
        sealers: Vec<T::AccountId>,
    ) -> (T::AccountId, u64) {
        let n: T::BlockNumber = (sealers.len() as u32).into();
        let index = block_number % n;
        let index_as_u64 = TryInto::<u64>::try_into(index)
            .ok()
            .expect("BockNumber to u64 type conversion failed!");
        let sealer: T::AccountId = sealers[index_as_u64 as usize].clone();
        debug::info!("it is sealer {:?} (index: {:?})", sealer, index);
        (sealer, index_as_u64)
    }
}
