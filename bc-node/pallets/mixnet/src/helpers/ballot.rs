use crate::types::{Ballot, Cipher, VoteId};
use crate::{Ballots, Ciphers, Module, Trait};
use frame_support::storage::{StorageDoubleMap, StorageMap};
use sp_std::vec::Vec;

/// all functions related to ballot operations in the offchain worker
pub fn store_ballot<T: Trait>(from: &T::AccountId, vote_id: &VoteId, ballot: Ballot) {
    // store the encrypted ballot
    Ballots::<T>::insert(vote_id, from, ballot.clone());

    for (topic_id, cipher) in ballot.answers {
        // store the encrypted cipher with the respective topic_id
        let mut ciphers: Vec<Cipher> = Module::<T>::ciphers(&topic_id);
        ciphers.push(cipher);
        Ciphers::insert(&topic_id, ciphers);
    }
}

// TODO: create function to append shuffled ciphers to storage (ShuffledCiphers)
