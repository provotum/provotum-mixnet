use crate::types::{Ballot, PublicKey as SubstratePK, QAsBigUint};
use crate::*;
use crate::{Error, Module, Trait};
use crypto::encryption::ElGamal;
use crypto::types::Cipher;
use frame_support::debug;
use num_bigint::BigUint;
use sp_std::vec::Vec;

/// all functions related to random value generation in the offchain worker
impl<T: Trait> Module<T> {
    pub fn store_ballot(from: T::AccountId, ballot: Ballot) {
        // store the encrypted ballot
        let mut ballots: Vec<Ballot> = Ballots::get();
        ballots.push(ballot.clone());
        Ballots::put(ballots);
        debug::info!("Encrypted Ballot: {:?} has been stored.", ballot);

        // update the list of voters
        let mut voters: Vec<T::AccountId> = Voters::<T>::get();
        voters.push(from.clone());
        Voters::<T>::put(voters);
        debug::info!("Voter {:?} has been stored.", from);
    }

    pub fn shuffle_ballots() -> Result<(Vec<Cipher>, Vec<BigUint>, Vec<usize>), Error<T>> {
        // get the system public key
        let pk: SubstratePK = PublicKey::get().ok_or(Error::<T>::PublicKeyNotExistsError)?;
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
        let ciphers: Vec<Cipher> = ballots
            .into_iter()
            .map(|c| c.into())
            .collect::<Vec<Cipher>>();

        // shuffle the ballots
        let shuffle = ElGamal::shuffle(&ciphers, &permutation, &randoms, &(pk.into()));
        let shuffled_ciphers: Vec<Cipher> = shuffle.into_iter().map(|item| item.0).collect();

        // type conversion: Cipher (BigUint) to Ballot (Vec<u8>)
        let shuffled_ballots: Vec<Ballot> = shuffled_ciphers
            .into_iter()
            .map(|c| c.into())
            .collect::<Vec<Ballot>>();

        // store the ballots on chain
        Ballots::put(shuffled_ballots);
        debug::info!("The ballots have been shuffled");
        Ok((ciphers, randoms, permutation))
    }

    fn shuffle_proof() {}
}
