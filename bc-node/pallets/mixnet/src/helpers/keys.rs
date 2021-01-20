use super::assertions::ensure_vote_exists;
use crate::{
    sp_api_hidden_includes_decl_storage::hidden_include::StorageMap,
    types::{PublicKey, PublicKeyShare, PublicParameters, Vote, VoteId},
    Error, PublicKeyShares, Trait, Votes,
};
use crypto::types::PublicKey as ElGamalPK;
use frame_support::ensure;
use num_bigint::BigUint;
use num_traits::One;
use sp_std::vec::Vec;

/// all functions related to key generation and decrypted share operations
pub fn get_public_params<T: Trait>(vote_id: &VoteId) -> Result<PublicParameters, Error<T>> {
    ensure_vote_exists(vote_id)?;

    // get the vote and extract the params
    let vote: Vote<T::AccountId> = Votes::<T>::get(&vote_id);
    Ok(vote.params)
}

/// all functions related to key generation and decrypted share operations
pub fn combine_shares<T: Trait>(vote_id: &VoteId) -> Result<PublicKey, Error<T>> {
    // get the public parameters
    let params: PublicParameters = get_public_params::<T>(&vote_id)?;
    let shares: Vec<PublicKeyShare> = PublicKeyShares::get(&vote_id);

    // check that there are at least two shares
    ensure!(shares.len() > 1, Error::<T>::NotEnoughPublicKeyShares);

    let shares: Vec<Vec<u8>> = shares
        .iter()
        .map(|share| share.pk.clone())
        .collect::<Vec<Vec<u8>>>();
    let shares: Vec<BigUint> = shares
        .iter()
        .map(|share| BigUint::from_bytes_be(share))
        .collect::<Vec<BigUint>>();

    let base: ElGamalPK = ElGamalPK {
        h: BigUint::one(),
        params: params.into(),
    };

    // combine the shares into a single key
    let new_pk = base.combine_public_keys_bigunits(&shares);
    Ok(new_pk.into())
}
