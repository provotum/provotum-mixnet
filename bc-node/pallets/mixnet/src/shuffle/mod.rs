pub mod prover;
pub mod shuffle;
pub mod verifier;

use crate::{
    helpers::{array::get_slice, params::get_public_key},
    types::{
        Cipher, NrOfShuffles, PublicKey as SubstratePK, ShufflePayload, ShuffleProof,
        ShuffleState, TopicId, VoteId, Wrapper,
    },
};
use crate::{Ciphers, Error, Module, ShuffleProofs, ShuffleStateStore, Trait};
use alloc::vec::Vec;
use crypto::types::{Cipher as BigCipher, PublicKey as ElGamalPK};
use frame_support::{
    ensure,
    storage::{StorageDoubleMap, StorageMap},
};

impl<T: Trait> Module<T> {
    const NR_OF_SHUFFLES: u8 = 3;

    pub fn verify_proof_store_shuffled_ciphers(
        vote_id: &VoteId,
        topic_id: &TopicId,
        payload: ShufflePayload,
    ) -> Result<(), Error<T>> {
        let proof: ShuffleProof = payload.proof.clone().into();
        let shuffled_ciphers: Vec<Cipher> = payload.ciphers.clone();
        let iteration: NrOfShuffles = payload.iteration;
        let start_position: u64 = payload.start_position;
        let batch_size: u64 = payload.batch_size;

        // get all encrypted votes (ciphers)
        // for the topic with id: topic_id and the # of shuffles already performed (iteration)
        let ciphers: Vec<Cipher> = Ciphers::get(topic_id, iteration);
        let total_ciphers = ciphers.len();

        // check if there are any ciphers for the given nr_of_shuffles
        if ciphers.is_empty() {
            return Err(Error::<T>::NrOfShufflesDoesNotExist);
        }

        // get shuffle state
        let shuffle_state: ShuffleState = ShuffleStateStore::get((vote_id, topic_id))
            .expect("shuffle state should exist for all existing votes & topics!");

        if shuffle_state.done {
            return Err(Error::<T>::ShuffleAlreadyCompleted);
        }

        // check prerequisites
        // - start_position must match
        // - batch_size must match
        // - # of ciphers must be <= batch_size (actually, mostly ==, but edge case when last batch is smaller than batch_size)
        if shuffle_state.iteration != iteration
            || shuffle_state.start_position != start_position
            || shuffle_state.batch_size != batch_size
            || shuffled_ciphers.len() > shuffle_state.batch_size as usize
        {
            return Err(Error::<T>::ShuffleStateIncorrect);
        }

        //
        // State: The votes exist and have not been shuffled yet!
        //

        // get the public key for the vote
        let pk: SubstratePK = get_public_key::<T>(vote_id)?;
        let pk: ElGamalPK = pk.into();

        // type conversion: Vec<Cipher> (Vec<Vec<u8>>) to Vec<BigCipher> (Vec<BigUint>)
        let big_ciphers: Vec<BigCipher> = Wrapper(ciphers).into();
        let big_shuffled_ciphers: Vec<BigCipher> =
            Wrapper(shuffled_ciphers.clone()).into();

        // get the required range of ciphers
        let slice: Vec<BigCipher> =
            get_slice::<T, BigCipher>(big_ciphers, start_position, batch_size);

        // verify the shuffle proof
        let is_proof_valid = Self::verify_shuffle_proof(
            &topic_id,
            proof,
            slice,
            big_shuffled_ciphers,
            &pk,
        )?;
        ensure!(is_proof_valid, Error::<T>::ShuffleProofVerifcationFailed);

        // store the shuffle ciphers with the new increased shuffle iteration
        let next_iteration = iteration + 1;
        let mut already_shuffled: Vec<Cipher> = Ciphers::get(topic_id, next_iteration);
        already_shuffled.extend(shuffled_ciphers.iter().cloned());
        Ciphers::insert(&topic_id, next_iteration, already_shuffled);

        // store the shuffle proof payload for verification (audit trail)
        let mut shuffle_proofs: Vec<ShufflePayload> =
            ShuffleProofs::get((&vote_id, &topic_id));
        shuffle_proofs.push(payload);
        ShuffleProofs::insert((&vote_id, &topic_id), shuffle_proofs);

        // compute the new shuffle state
        let new_state: ShuffleState = Self::compute_next_shuffle_state(
            start_position,
            batch_size,
            total_ciphers,
            iteration,
        );

        // update the shuffle state
        ShuffleStateStore::insert((vote_id, topic_id), new_state);
        Ok(())
    }

    fn compute_next_shuffle_state(
        start_position: u64,
        batch_size: u64,
        nr_ciphers: usize,
        iteration: u8,
    ) -> ShuffleState {
        let next_iteration = iteration + 1;

        // compute potential new start position for shuffle batch
        let new_start_position = start_position + batch_size;

        // compute new iteration -> check if new start position would be too large, and, therefore, start again...
        let new_iteration = if new_start_position as usize >= nr_ciphers {
            next_iteration
        } else {
            iteration
        };

        // check if iteration has been increase, if so, we need to reset the start position
        let new_start_position = if new_iteration != iteration {
            0
        } else {
            new_start_position
        };

        // check if shuffling is completed
        let done = if new_iteration >= Self::NR_OF_SHUFFLES {
            true
        } else {
            false
        };

        ShuffleState {
            iteration: new_iteration,
            start_position: new_start_position,
            batch_size,
            done,
        }
    }
}
