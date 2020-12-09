use frame_support::debug;

use crate::{Error, Module, Trait};

pub fn ensure_voting_authority<T: Trait>(account_id: &T::AccountId) -> Result<(), Error<T>> {
    let voting_authorities = Module::<T>::voting_authorities();
    match voting_authorities.binary_search(&account_id) {
        Ok(_) => Ok(()),
        Err(_) => {
            debug::info!("Requester is not a voting authority!");
            Err(Error::<T>::NotAVotingAuthority)?
        }
    }
}
