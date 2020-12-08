use crate::sp_api_hidden_includes_decl_storage::hidden_include::StorageValue;
use crate::types::Ballot;
use crate::{Ballots, Module, Trait, Voters};
use frame_support::debug;
use sp_std::vec::Vec;

/// all functions related to ballot operations in the offchain worker
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
}
