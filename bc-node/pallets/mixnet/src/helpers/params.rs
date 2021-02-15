use super::assertions::ensure_vote_exists;
use crate::{
    types::{PublicKey as SubstratePK, PublicParameters, Vote, VoteId},
    Error, PublicKey, Trait, Votes,
};
use frame_support::storage::StorageMap;

/// all functions related to key generation and decrypted share operations
pub fn get_public_params<T: Trait>(
    vote_id: &VoteId,
) -> Result<PublicParameters, Error<T>> {
    ensure_vote_exists(vote_id)?;

    // get the vote and extract the params
    let vote: Vote<T::AccountId> = Votes::<T>::get(vote_id);
    Ok(vote.params)
}

pub fn get_public_key<T: Trait>(vote_id: &VoteId) -> Result<SubstratePK, Error<T>> {
    PublicKey::get(vote_id).ok_or(Error::<T>::PublicKeyNotExistsError)
}
