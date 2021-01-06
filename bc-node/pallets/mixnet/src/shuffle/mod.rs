pub mod prover;
pub mod verifier;

use crate::sp_api_hidden_includes_decl_storage::hidden_include::{StorageMap, StorageValue};
use crate::types::{Cipher, PublicKey as SubstratePK, QAsBigUint, TopicId, Wrapper};
use crate::{Ciphers, Error, Module, PublicKey, Trait};
use crypto::encryption::ElGamal;
use crypto::types::Cipher as BigCipher;
use num_bigint::BigUint;
use sp_std::vec::Vec;

/// all functions related to ballot operations in the offchain worker
impl<T: Trait> Module<T> {
    pub fn shuffle_ciphers(
        topic_id: &TopicId,
    ) -> Result<(Vec<BigCipher>, Vec<BigUint>, Vec<usize>), Error<T>> {
        // get the system public key
        let pk: SubstratePK = PublicKey::get().ok_or(Error::<T>::PublicKeyNotExistsError)?;
        let q = QAsBigUint::q(&pk.params);

        // get the encrypted ballots stored on chain
        let ciphers: Vec<Cipher> = Ciphers::get(topic_id);
        let size = ciphers.len();

        // check that there are ballots to shuffle
        if size == 0 {
            return Err(Error::<T>::ShuffleCiphersSizeZeroError);
        }

        // get the permuation or else return error
        let permutation: Vec<usize> = Self::generate_permutation(size)?;

        // get the random values
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(&q, size)?;

        // type conversion: Ballot (Vec<u8>) to BigCipher (BigUint)
        let ciphers: Vec<BigCipher> = Wrapper(ciphers).into();

        // shuffle the ciphers
        let shuffle = ElGamal::shuffle(&ciphers, &permutation, &randoms, &(pk.into()));
        let shuffled_ciphers: Vec<BigCipher> = shuffle.into_iter().map(|item| item.0).collect();

        // return the shuffled ciphers, randoms, permutation as result
        Ok((shuffled_ciphers, randoms, permutation))
    }
}
