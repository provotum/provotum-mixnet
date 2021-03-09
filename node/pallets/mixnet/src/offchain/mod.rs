mod send;

use crate::{
    helpers::{array::get_slice, assertions::ensure_vote_exists, params::get_public_key},
    types::{
        Ballot, Cipher, PublicKey as SubstratePK, ShufflePayload, ShuffleProof,
        ShuffleState, Topic, TopicId, Vote, VoteId, VotePhase, Wrapper,
    },
};
use crate::{
    Call, Ciphers, Error, Module, Sealers, ShuffleStateStore, Topics, Trait, VoteIds,
    Votes,
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
use frame_system::offchain::{Account, SendSignedTransaction, Signer};
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

    pub fn offchain_shuffling(block_number: T::BlockNumber) -> Result<(), Error<T>> {
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

            for (topic_id, _) in topics.iter() {
                // get shuffle state
                let shuffle_state: ShuffleState = ShuffleStateStore::get((
                    vote_id, topic_id,
                ))
                .expect("shuffle state should exist for all existing votes & topics!");
                debug::info!("shuffle_state: {:?}", shuffle_state);

                // if the shuffling has been completed -> skip to next topic
                if shuffle_state.done {
                    continue;
                }

                // check who's turn it is
                let sealers: Vec<T::AccountId> = Sealers::<T>::get();
                let current_sealer = Self::get_current_sealer(block_number, sealers);

                // get the signer for the transaction
                let signer = Signer::<T, T::AuthorityId>::any_account();

                // if it's the current_sealer's turn, then shuffle + submit ciphers + proof
                // else, submit empty transaction
                let transaction_response = signer.send_signed_transaction(|_acct| {
                    let local_address = &_acct.id;

                    if current_sealer.eq(local_address) {
                        debug::info!("my turn!");
                        // shuffle ciphers + create proof
                        let payload_response = Self::offchain_shuffle_and_proof(
                            &topic_id,
                            shuffle_state.iteration,
                            &pk,
                            shuffle_state.start_position,
                            shuffle_state.batch_size,
                        );
                        let payload: ShufflePayload = payload_response.unwrap();
                        Call::submit_shuffled_votes_and_proof(
                            vote_id.to_vec(),
                            topic_id.to_vec(),
                            payload,
                        )
                    // do nothing in case that it is not this sealer's turn
                    } else {
                        debug::info!("not my turn!");
                        Call::do_nothing_when_its_not_your_turn()
                    }
                });
                Self::handle_transaction_response(
                    &vote_id,
                    &current_sealer,
                    transaction_response,
                )?;
            }
        }
        Ok(())
    }

    pub fn offchain_shuffle_and_proof(
        topic_id: &TopicId,
        iteration: u8,
        pk: &ElGamalPK,
        start_position: u64,
        batch_size: u64,
    ) -> Result<ShufflePayload, Error<T>> {
        // get all encrypted votes (ciphers)
        // for the topic with id: topic_id and the # of shuffles (iteration)
        debug::info!("topic_id: {:?}", topic_id);
        let ciphers: Vec<Cipher> = Ciphers::get(&topic_id, iteration);

        // type conversion: Cipher (Vec<u8>) to BigCipher (BigUint)
        let encryptions: Vec<BigCipher> = Wrapper(ciphers).into();

        // retrieve the ciphers for the computed range
        let slice =
            get_slice::<T, BigCipher>(encryptions.clone(), start_position, batch_size);

        // for each topic_id & vote_id
        // shuffle the votes
        let (shuffled_slice, re_encryption_randoms, permutation): (
            Vec<BigCipher>,
            Vec<BigUint>,
            Vec<usize>,
        ) = Self::shuffle_ciphers(&pk, slice.to_vec())?;

        // generate the shuffle proof
        let proof: ShuffleProof = Self::generate_shuffle_proof(
            &topic_id,
            slice,
            shuffled_slice.clone(),
            re_encryption_randoms,
            &permutation,
            &pk,
        )?;

        // create transaction payload
        let payload = ShufflePayload {
            ciphers: Wrapper(shuffled_slice).into(),
            proof: proof.into(),
            iteration,
            start_position,
            batch_size,
        };
        Ok(payload)
    }

    /// retrieves the current sealer, depends on the block number
    fn get_current_sealer(
        block_number: T::BlockNumber,
        sealers: Vec<T::AccountId>,
    ) -> T::AccountId {
        let n: T::BlockNumber = (sealers.len() as u32).into();
        let index = block_number % n;
        let index_as_u64 = TryInto::<u64>::try_into(index)
            .ok()
            .expect("BockNumber to u64 type conversion failed!");
        let sealer: T::AccountId = sealers[index_as_u64 as usize].clone();
        debug::info!("current turn: sealer {:?} (index: {:?})", sealer, index);
        sealer
    }

    fn handle_transaction_response(
        vote_id: &VoteId,
        current_sealer: &T::AccountId,
        transaction_response: Option<(Account<T>, Result<(), ()>)>,
    ) -> Result<(), Error<T>> {
        // handle the response
        if let Some((acc, res)) = transaction_response {
            // display error if the signed tx fails.
            if res.is_err() {
                debug::error!(
                    "failure in offchain tx, acc: {:?}, res: {:?}",
                    acc.id,
                    res
                );
            }
            // transaction is sent successfully
            if current_sealer.eq(&acc.id) {
                debug::info!(
                    "votes shuffled in offchain worker -> vote_id: {:?}",
                    vote_id
                );
            }
            Ok(())
        } else {
            // the case of `None`: no account is available for sending
            debug::error!("No local account available");
            return Err(<Error<T>>::NoLocalAcctForSigning);
        }
    }
}
