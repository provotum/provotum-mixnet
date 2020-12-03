pub mod prover;
pub mod verifier;

use crate::sp_api_hidden_includes_decl_storage::hidden_include::StorageValue;
use crate::types::{PublicKey as SubstratePK, QAsBigUint, Wrapper};
use crate::{Ballots, Error, Module, PublicKey, Trait};
use crypto::encryption::ElGamal;
use crypto::types::Cipher;
use frame_support::debug;
use num_bigint::BigUint;
use sp_std::vec::Vec;

/// all functions related to ballot operations in the offchain worker
impl<T: Trait> Module<T> {
    pub fn shuffle_ballots() -> Result<(Vec<Cipher>, Vec<BigUint>, Vec<usize>), Error<T>>
    {
        // get the system public key
        let pk: SubstratePK =
            PublicKey::get().ok_or(Error::<T>::PublicKeyNotExistsError)?;
        let q = QAsBigUint::q(&pk.params);

        // get the encrypted ballots stored on chain
        let ballots = Ballots::get();
        let size = ballots.len();

        // check that there are ballots to shuffle
        if size == 0 {
            return Err(Error::<T>::ShuffleBallotsSizeZeroError);
        }

        // get the permuation or else return error
        let permutation: Vec<usize> = Self::generate_permutation(size)?;

        // get the random values
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(&q, size)?;

        // type conversion: Ballot (Vec<u8>) to Cipher (BigUint)
        let ciphers: Vec<Cipher> = Wrapper(ballots).into();

        // shuffle the ballots
        let shuffle = ElGamal::shuffle(&ciphers, &permutation, &randoms, &(pk.into()));
        let shuffled_ciphers: Vec<Cipher> =
            shuffle.into_iter().map(|item| item.0).collect();

        // store the ballots on chain
        debug::info!("The ballots have been shuffled");
        Ok((shuffled_ciphers, randoms, permutation))
    }
}
