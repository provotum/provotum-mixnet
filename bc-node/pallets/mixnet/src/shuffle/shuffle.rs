use crate::{Error, Module, Trait};
use crypto::encryption::ElGamal;
use crypto::types::{Cipher as BigCipher, PublicKey as ElGamalPK};
use num_bigint::BigUint;
use sp_std::vec::Vec;

/// all functions related to ballot operations in the offchain worker
impl<T: Trait> Module<T> {
    pub fn shuffle_ciphers(
        pk: &ElGamalPK,
        ciphers: Vec<BigCipher>,
    ) -> Result<(Vec<BigCipher>, Vec<BigUint>, Vec<usize>), Error<T>> {
        let q = pk.params.q();
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
        let shuffle = ElGamal::shuffle(&ciphers, &permutation, &randoms, &pk);
        let shuffled_ciphers: Vec<BigCipher> =
            shuffle.into_iter().map(|item| item.0).collect();

        // return the shuffled ciphers, randoms, permutation as result
        Ok((shuffled_ciphers, randoms, permutation))
    }
}
