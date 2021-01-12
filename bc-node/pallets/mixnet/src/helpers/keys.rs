use super::assertions::ensure_vote_exists;
use crate::sp_api_hidden_includes_decl_storage::hidden_include::StorageMap;
use crate::types::{PublicParameters, Vote, VoteId};
use crate::{Error, Trait, Votes};

/// all functions related to key generation and decrypted share operations
pub fn get_public_params<T: Trait>(vote_id: &VoteId) -> Result<PublicParameters, Error<T>> {
    ensure_vote_exists(vote_id)?;

    // get the vote and extract the params
    let vote: Vote<T::AccountId> = Votes::<T>::get(&vote_id);
    Ok(vote.params)
}
