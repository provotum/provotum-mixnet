pub mod prover;
pub mod shuffle;
pub mod verifier;

use crate::{
    helpers::params::get_public_key,
    types::{
        Cipher, NrOfShuffles, PublicKey as SubstratePK, ShuffleProof,
        ShuffleProofAsBytes, TopicId, VoteId, Wrapper,
    },
};
use crate::{Ciphers, Error, Module, Trait};
use alloc::vec::Vec;
use crypto::types::{Cipher as BigCipher, PublicKey as ElGamalPK};
use frame_support::{debug, ensure, storage::StorageDoubleMap};

impl<T: Trait> Module<T> {
    pub fn verify_proof_store_shuffled_ciphers(
        vote_id: &VoteId,
        topic_id: &TopicId,
        proof: ShuffleProofAsBytes,
        shuffled_encryptions: Vec<Cipher>,
        nr_of_shuffles: NrOfShuffles,
    ) -> Result<(), Error<T>> {
        // get the public key for the vote
        let pk: SubstratePK = get_public_key::<T>(vote_id)?;

        // get all encrypted votes (encryptions)
        // for the topic with id: topic_id and the # of shuffles (nr_of_shuffles)
        let encryptions: Vec<Cipher> = Ciphers::get(topic_id, nr_of_shuffles);

        // check if there are any ciphers for the given nr_of_shuffles
        if encryptions.is_empty() {
            return Err(Error::<T>::NrOfShufflesDoesNotExist);
        }

        // type conversion: Vec<Cipher> (Vec<Vec<u8>>) to Vec<BigCipher> (Vec<BigUint>)
        let big_ciphers: Vec<BigCipher> = Wrapper(encryptions).into();
        let big_shuffled_ciphers: Vec<BigCipher> =
            Wrapper(shuffled_encryptions.clone()).into();
        let pk: ElGamalPK = pk.into();

        // transform the proof into the internal representation using BigUint
        let proof: ShuffleProof = proof.into();

        // verify the shuffle proof
        let is_proof_valid = Self::verify_shuffle_proof(
            &topic_id,
            proof,
            big_ciphers,
            big_shuffled_ciphers,
            &pk,
        )?;
        ensure!(is_proof_valid, Error::<T>::ShuffleProofVerifcationFailed);

        // check that no shuffle already exists for the increased number
        let new_nr_of_shuffles = nr_of_shuffles + 1;
        let already_shuffled: Vec<Cipher> = Ciphers::get(topic_id, new_nr_of_shuffles);
        debug::info!(
            "have the ciphers already been shuffled and stored? {:?}",
            res.is_empty()
        );
        ensure!(res.is_empty(), Error::<T>::ShuffleAlreadyPerformed);

        // store the shuffle ciphers with the new increased number of shuffles
        Ciphers::insert(&topic_id, new_nr_of_shuffles, shuffled_encryptions);

        Ok(())
    }
}
