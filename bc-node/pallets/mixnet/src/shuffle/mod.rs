pub mod prover;
pub mod shuffle;
pub mod verifier;

use crate::{
    helpers::params::get_public_key,
    types::{
        Cipher, NrOfShuffles, PublicKey as SubstratePK, ShufflePayload, ShuffleProof,
        TopicId, VoteId, Wrapper,
    },
};
use crate::{Ciphers, Error, Module, ShuffleProofs, Trait};
use alloc::vec::Vec;
use crypto::types::{Cipher as BigCipher, PublicKey as ElGamalPK};
use frame_support::{
    debug, ensure,
    storage::{StorageDoubleMap, StorageMap},
};

impl<T: Trait> Module<T> {
    pub fn verify_proof_store_shuffled_ciphers(
        vote_id: &VoteId,
        topic_id: &TopicId,
        payload: ShufflePayload,
    ) -> Result<(), Error<T>> {
        let proof: ShuffleProof = payload.proof.clone().into();
        let shuffled_ciphers: Vec<Cipher> = payload.ciphers.clone();
        let iteration: NrOfShuffles = payload.iteration;

        // get all encrypted votes (ciphers)
        // for the topic with id: topic_id and the # of shuffles already performed (iteration)
        let ciphers: Vec<Cipher> = Ciphers::get(topic_id, iteration);

        // check if there are any ciphers for the given nr_of_shuffles
        if ciphers.is_empty() {
            return Err(Error::<T>::NrOfShufflesDoesNotExist);
        }

        // check that the ciphers have not already been shuffled
        // i.e. no votes exist for the increased nr_of_shuffles
        let new_iteration = iteration + 1;
        let already_shuffled: Vec<Cipher> = Ciphers::get(topic_id, new_iteration);
        debug::info!(
            "vote_id: {:?}, topic_id: {:?}, ciphers shuffled & stored? {:?}",
            vote_id,
            topic_id,
            !already_shuffled.is_empty()
        );
        ensure!(
            already_shuffled.is_empty(),
            Error::<T>::ShuffleAlreadyPerformed
        );

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

        // verify the shuffle proof
        let is_proof_valid = Self::verify_shuffle_proof(
            &topic_id,
            proof,
            big_ciphers,
            big_shuffled_ciphers,
            &pk,
        )?;
        ensure!(is_proof_valid, Error::<T>::ShuffleProofVerifcationFailed);

        // store the shuffle ciphers with the new increased number of shuffles
        Ciphers::insert(&topic_id, new_iteration, shuffled_ciphers);

        // store the shuffle proof payload for verification (audit trail)
        let mut shuffle_proofs: Vec<ShufflePayload> =
            ShuffleProofs::get((&vote_id, &topic_id));
        shuffle_proofs.push(payload);
        ShuffleProofs::insert((&vote_id, &topic_id), shuffle_proofs);

        Ok(())
    }
}
