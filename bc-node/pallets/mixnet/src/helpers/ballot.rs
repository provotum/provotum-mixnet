use crate::types::{Ballot, Cipher, VoteId};
use crate::{Ballots, Ciphers, Trait};
use frame_support::storage::StorageDoubleMap;
use sp_std::vec::Vec;

const INITIAL_NUMBER_OF_SHUFFLES: u8 = 0;

/// all functions related to ballot operations in the offchain worker
pub fn store_ballot<T: Trait>(from: &T::AccountId, vote_id: &VoteId, ballot: Ballot) {
    // store the encrypted ballot
    Ballots::<T>::insert(vote_id, from, ballot.clone());

    for (topic_id, cipher) in ballot.answers {
        // store the encrypted cipher with the respective topic_id
        // # of shuffles is always 0 -> since the voter has just submitted the vote
        let mut ciphers: Vec<Cipher> =
            Ciphers::get(&topic_id, INITIAL_NUMBER_OF_SHUFFLES);
        ciphers.push(cipher);

        // store the
        Ciphers::insert(&topic_id, INITIAL_NUMBER_OF_SHUFFLES, ciphers);
    }
}

// TODO: create function to append shuffled ciphers to storage (ShuffledCiphers)
