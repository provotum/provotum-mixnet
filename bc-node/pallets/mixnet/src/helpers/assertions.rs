use crate::sp_api_hidden_includes_decl_storage::hidden_include::StorageMap;
use crate::{types::VoteId, Error, Module, Trait, Votes};
use frame_support::{debug, ensure};

pub fn ensure_voting_authority<T: Trait>(account_id: &T::AccountId) -> Result<(), Error<T>> {
    let voting_authorities = Module::<T>::voting_authorities();
    match voting_authorities.binary_search(&account_id) {
        Ok(_) => Ok(()),
        Err(_) => {
            debug::info!("Requester is not a voting authority!");
            return Err(Error::<T>::NotAVotingAuthority);
        }
    }
}

pub fn ensure_sealer<T: Trait>(account_id: &T::AccountId) -> Result<(), Error<T>> {
    let sealers = Module::<T>::sealers();
    match sealers.binary_search(&account_id) {
        Ok(_) => Ok(()),
        Err(_) => {
            debug::info!("Requester is not a sealer!");
            return Err(Error::<T>::NotASealer);
        }
    }
}

pub fn ensure_vote_exists<T: Trait>(vote_id: &VoteId) -> Result<(), Error<T>> {
    // check that the vote_id exists
    ensure!(
        Votes::<T>::contains_key(vote_id),
        Error::<T>::VoteDoesNotExist
    );
    Ok(())
}
