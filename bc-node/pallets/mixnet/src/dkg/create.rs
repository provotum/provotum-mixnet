use crate::{
    helpers::params::get_public_params,
    helpers::phase::set_phase,
    types::{
        PublicKey as SubstratePK, PublicKeyShare, PublicParameters, VoteId, VotePhase,
    },
    Error, PublicKey, PublicKeyShares, Trait,
};
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use crypto::types::PublicKey as ElGamalPK;
use frame_support::{debug, ensure, storage::StorageMap};
use num_bigint::BigUint;
use num_traits::One;

/// all functions related to key generation and decrypted share operations
pub fn combine_shares<T: Trait>(
    who: T::AccountId,
    vote_id: &VoteId,
) -> Result<SubstratePK, Error<T>> {
    // get the public parameters
    let params: PublicParameters = get_public_params::<T>(&vote_id)?;
    let shares: Vec<PublicKeyShare> = PublicKeyShares::get(&vote_id);

    // check that there are at least two shares
    ensure!(shares.len() > 1, Error::<T>::NotEnoughPublicKeyShares);

    let pk_shares_bytes: Vec<Vec<u8>> = shares
        .iter()
        .map(|share| share.pk.clone())
        .collect::<Vec<Vec<u8>>>();
    let pk_shares_biguint: Vec<BigUint> = pk_shares_bytes
        .iter()
        .map(|share| BigUint::from_bytes_be(share))
        .collect::<Vec<BigUint>>();

    let base: ElGamalPK = ElGamalPK {
        h: BigUint::one(),
        params: params.into(),
    };

    // combine the shares into a single key
    let new_pk: ElGamalPK = base.combine_public_keys_bigunits(&pk_shares_biguint);
    let pk: SubstratePK = new_pk.into();
    PublicKey::insert(vote_id.to_owned(), pk.clone());
    debug::info!("public_key successfully generated!");

    // advance the voting phase to the next stage
    set_phase::<T>(&who, &vote_id, VotePhase::Voting)?;
    Ok(pk)
}
