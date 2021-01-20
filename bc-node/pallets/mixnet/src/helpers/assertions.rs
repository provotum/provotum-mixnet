use crate::sp_api_hidden_includes_decl_storage::hidden_include::StorageMap;
use crate::{types::VoteId, Error, Module, Trait, Votes};
use frame_support::{debug, ensure};

pub fn ensure_voting_authority<T: Trait>(account_id: &T::AccountId) -> Result<(), Error<T>> {
    let voting_authorities = Module::<T>::voting_authorities();
    match voting_authorities.contains(account_id) {
        true => Ok(()),
        false => {
            debug::info!("Requester {:?} is not a voting authority!", account_id);
            return Err(Error::<T>::NotAVotingAuthority);
        }
    }
}

pub fn ensure_not_a_voting_authority<T: Trait>(account_id: &T::AccountId) -> Result<(), Error<T>> {
    let voting_authorities = Module::<T>::voting_authorities();
    match voting_authorities.contains(account_id) {
        true => {
            debug::info!("Requester is a voting authority!");
            return Err(Error::<T>::IsVotingAuthority);
        }
        false => Ok(()),
    }
}

pub fn ensure_sealer<T: Trait>(account_id: &T::AccountId) -> Result<(), Error<T>> {
    let sealers = Module::<T>::sealers();
    match sealers.contains(account_id) {
        true => Ok(()),
        false => {
            debug::info!("Requester: {:?} is not a sealer!", account_id);
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
