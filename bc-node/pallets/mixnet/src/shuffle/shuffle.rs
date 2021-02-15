use crate::{
    helpers::params::get_public_key,
    types::{
        Cipher, NrOfShuffles, PublicKey as SubstratePK, QAsBigUint, TopicId, VoteId,
        Wrapper,
    },
};
use crate::{Ciphers, Error, Module, Trait};
use crypto::encryption::ElGamal;
use crypto::types::Cipher as BigCipher;
use frame_support::storage::StorageDoubleMap;
use num_bigint::BigUint;
use sp_std::vec::Vec;

/// all functions related to ballot operations in the offchain worker
impl<T: Trait> Module<T> {
    pub fn shuffle_ciphers(
        vote_id: &VoteId,
        topic_id: &TopicId,
        nr_of_shuffles: NrOfShuffles,
    ) -> Result<(Vec<BigCipher>, Vec<BigUint>, Vec<usize>), Error<T>> {
        // get the system public key
        let pk: SubstratePK = get_public_key(&vote_id)?.into();
        let q = QAsBigUint::q(&pk.params);

        // get all encrypted votes (ciphers)
        // for the topic with id: topic_id and the # of shuffles (nr_of_shuffles)
        let ciphers: Vec<Cipher> = Ciphers::get(&topic_id, nr_of_shuffles);

        // type conversion: Ballot (Vec<u8>) to BigCipher (BigUint)
        let ciphers: Vec<BigCipher> = Wrapper(ciphers).into();

        let size = ciphers.len();

        // check that there are ballots to shuffle
        if size == 0 {
            return Err(Error::<T>::ShuffleCiphersSizeZeroError);
        }

        // get the permuation or else return error
        let permutation: Vec<usize> = Self::generate_permutation(size)?;

        // get the random values
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(&q, size)?;

        // shuffle the ciphers
        let shuffle = ElGamal::shuffle(&ciphers, &permutation, &randoms, &(pk.into()));
        let shuffled_ciphers: Vec<BigCipher> =
            shuffle.into_iter().map(|item| item.0).collect();

        // // store the shuffle ciphers + increase the number of shuffles
        // Ciphers::insert(&topic_id, nr_of_shuffles + 1);
        // TODO: only store the votes once the proof has been verified...

        // return the shuffled ciphers, randoms, permutation as result
        Ok((shuffled_ciphers, randoms, permutation))
    }
}
