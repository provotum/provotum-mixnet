use crate::{
    types::{PublicKeyShare, VoteId},
    Error, PublicKeyShareBySealer, Trait,
};
use frame_support::storage::StorageMap;

pub fn get_public_keyshare<T: Trait>(
    vote_id: &VoteId,
    sealer: &T::AccountId,
) -> Result<PublicKeyShare, Error<T>> {
    PublicKeyShareBySealer::<T>::get::<(&VoteId, &T::AccountId)>((vote_id, sealer))
        .ok_or(Error::<T>::PublicKeyShareNotExistsError)
}
