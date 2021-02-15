use crate::dkg::helper::get_public_keyshare;
use crate::helpers::params::get_public_params;
use crate::types::{
    Cipher, DecryptedShare, DecryptedShareProof, NrOfShuffles, PublicKeyShare,
    PublicKeyShareProof, PublicParameters, TopicId, VoteId, Wrapper,
};
use crate::{
    Ciphers, DecryptedShares, Error, PublicKeyShareBySealer, PublicKeyShares, Trait,
};
use codec::Encode;
use crypto::proofs::{decryption::DecryptionProof, keygen::KeyGenerationProof};
use crypto::types::Cipher as BigCipher;
use frame_support::{
    debug, ensure,
    storage::{StorageDoubleMap, StorageMap},
};
use num_bigint::BigUint;
use sp_std::vec::Vec;

pub fn verify_proof_and_store_keygen_share<T: Trait>(
    who: T::AccountId,
    vote_id: &VoteId,
    pk_share: PublicKeyShare,
) -> Result<(), Error<T>> {
    // get the public parameters
    let params: PublicParameters = get_public_params::<T>(&vote_id)?;

    // verify the public key share proof
    let sealer_id = who.encode();
    let proof: PublicKeyShareProof = pk_share.proof.clone();
    let pk: BigUint = BigUint::from_bytes_be(&pk_share.pk);
    let proof_valid =
        KeyGenerationProof::verify(&params.into(), &pk, &proof.into(), &sealer_id);
    ensure!(proof_valid, Error::<T>::PublicKeyShareProofError);

    // store the public key share
    let mut shares: Vec<PublicKeyShare> = PublicKeyShares::get(&vote_id);
    shares.push(pk_share.clone());
    PublicKeyShares::insert(&vote_id, shares);
    PublicKeyShareBySealer::<T>::insert((&vote_id, &who), pk_share);
    debug::info!("public_key_share successfully submitted and proof verified!");
    Ok(())
}

pub fn verify_proof_and_store_decrypted_share<T: Trait>(
    who: T::AccountId,
    vote_id: &VoteId,
    topic_id: &TopicId,
    shares: Vec<DecryptedShare>,
    proof: DecryptedShareProof,
    nr_of_shuffles: &NrOfShuffles,
) -> Result<(), Error<T>> {
    // get the public parameters and the public key share of the sealer
    let sealer_id: &[u8] = &who.encode();
    let params: PublicParameters = get_public_params::<T>(vote_id)?;
    let sealer_pk_share: PublicKeyShare = get_public_keyshare::<T>(vote_id, &who)?;
    let sealer_pk: BigUint = BigUint::from_bytes_be(&sealer_pk_share.pk);

    // get all encrypted votes (ciphers)
    // for the topic with id: topic_id and the # of shuffles (nr_of_shuffles)
    let ciphers: Vec<Cipher> = Ciphers::get(topic_id, nr_of_shuffles);

    // type conversion: Vec<Cipher> (Vec<Vec<u8>>) to Vec<BigCipher> (Vec<BigUint>)
    let big_ciphers: Vec<BigCipher> = Wrapper(ciphers).into();

    // type conversion: DecryptedShare (Vec<u8>) to BigUint
    let decrypted_shares: Vec<BigUint> = shares
        .iter()
        .map(|s| BigUint::from_bytes_be(s))
        .collect::<Vec<BigUint>>();

    // verify the proof using the sealer's public key share
    let is_valid: bool = DecryptionProof::verify(
        &params.into(),
        &sealer_pk,
        &proof.into(),
        big_ciphers,
        decrypted_shares,
        sealer_id,
    );
    ensure!(is_valid, Error::<T>::DecryptedShareProofError);

    // store the decrypted shares
    let mut stored: Vec<DecryptedShare> =
        DecryptedShares::<T>::get::<&TopicId, &T::AccountId>(topic_id, &who);

    // check if the share has been already submitted. if not, store it.
    for share in shares.iter() {
        if !stored.contains(share) {
            stored.push(share.clone());
        }
    }

    // store the decrypted shares per topic and sealer
    DecryptedShares::<T>::insert(topic_id, &who, stored);
    Ok(())
}
