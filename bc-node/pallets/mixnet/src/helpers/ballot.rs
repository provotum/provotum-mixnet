use crate::sp_api_hidden_includes_decl_storage::hidden_include::{StorageDoubleMap, StorageMap};
use crate::types::{Ballot, Cipher, VoteId};
use crate::{Ballots, Ciphers, Module, Trait};
use sp_std::vec::Vec;

/// all functions related to ballot operations in the offchain worker
impl<T: Trait> Module<T> {
    pub fn store_ballot(from: &T::AccountId, vote_id: &VoteId, ballot: Ballot) {
        // store the encrypted ballot
        Ballots::<T>::insert(vote_id, from, ballot.clone());

        for (topic_id, cipher) in ballot.answers {
            // store the encrypted cipher with the respective topic_id
            let mut ciphers: Vec<Cipher> = Module::<T>::ciphers(&topic_id);
            ciphers.push(cipher);
            Ciphers::insert(&topic_id, ciphers);
        }
    }
}
