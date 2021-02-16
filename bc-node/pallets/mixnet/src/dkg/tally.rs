use crate::types::{
    Cipher, Count, DecryptedShare, NrOfShuffles, Plaintext, PublicParameters, TopicId,
    VoteId, Wrapper,
};
use crate::{
    helpers::params::get_public_params, Ciphers, DecryptedShares, Error, Sealers, Tally,
    Trait,
};
use crypto::encryption::ElGamal;
use crypto::types::Cipher as BigCipher;
use frame_support::{
    ensure,
    storage::{StorageDoubleMap, StorageMap, StorageValue},
};
use num_bigint::BigUint;
use num_traits::One;
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};

pub fn combine_shares_and_tally_topic<T: Trait>(
    vote_id: &VoteId,
    topic_id: &TopicId,
    encoded: bool,
    nr_of_shuffles: &NrOfShuffles,
) -> Result<BTreeMap<Plaintext, Count>, Error<T>> {
    // get the public parameters and the system public key
    let params: PublicParameters = get_public_params::<T>(vote_id)?;
    let big_p: BigUint = BigUint::from_bytes_be(&params.p);
    let big_g: BigUint = BigUint::from_bytes_be(&params.g);

    // get all encrypted votes (ciphers)
    // for the topic with id: topic_id and the # of shuffles (nr_of_shuffles)
    let ciphers: Vec<Cipher> = Ciphers::get(topic_id, nr_of_shuffles);

    // type conversion: Vec<Cipher> (Vec<Vec<u8>>) to Vec<BigCipher> (Vec<BigUint>)
    let big_ciphers: Vec<BigCipher> = Wrapper(ciphers).into();

    // retrieve the decrypted shares of all sealers
    let sealers: Vec<T::AccountId> = Sealers::<T>::get();
    let mut partial_decryptions: Vec<Vec<BigUint>> = Vec::with_capacity(sealers.len());

    for sealer in sealers.iter() {
        // get the partial decryptions of each sealer
        let shares: Vec<DecryptedShare> =
            DecryptedShares::<T>::get::<&TopicId, &T::AccountId>(topic_id, &sealer);

        // make sure that each sealer has submitted his decrypted shares
        ensure!(!shares.is_empty(), Error::<T>::NotEnoughDecryptedShares);

        // type conversion: DecryptedShare (Vec<u8>) to BigUint
        let big_shares: Vec<BigUint> = shares
            .iter()
            .map(|s| BigUint::from_bytes_be(s))
            .collect::<Vec<BigUint>>();
        partial_decryptions.push(big_shares);
    }

    // combine all partial decryptions by all sealers
    let combined_partial_decryptions =
        ElGamal::combine_partial_decrypted_as(partial_decryptions, &big_p);

    // retrieve the plaintext votes
    // by combining the decrypted components a with their decrypted components b
    let iterator = big_ciphers.iter().zip(combined_partial_decryptions.iter());
    let mut plaintexts = iterator
        .map(|(cipher, decrypted_a)| {
            ElGamal::partial_decrypt_b(&cipher.b, decrypted_a, &big_p)
        })
        .collect::<Vec<BigUint>>();

    // if the votes were encoded, we need to decoded them (brute force dlog)
    if encoded {
        plaintexts = plaintexts
            .iter()
            .map(|encoded| ElGamal::decode_message(encoded, &big_g, &big_p))
            .collect::<Vec<BigUint>>();
    }

    // get the tally for the vote with topic id: topic_id
    let tally: Option<BTreeMap<Plaintext, Count>> = Tally::get::<&TopicId>(topic_id);

    // check that topic has not been tallied yet
    ensure!(tally.is_none(), Error::<T>::TopicHasAlreadyBeenTallied);

    // count the number of votes per voting option
    // store result as a map -> key: voting option, value: count
    let one = BigUint::one();
    let mut big_results: BTreeMap<BigUint, BigUint> = BTreeMap::new();
    plaintexts
        .into_iter()
        .for_each(|item| *big_results.entry(item).or_default() += &one);

    // type conversion: BTreeMap<BigUint, BigUint> to BTreeMap<Vec<u8>, Vec<u8>>
    // to be able to store the results on chain
    let mut results: BTreeMap<Plaintext, Count> = BTreeMap::new();
    for (key, value) in big_results.iter() {
        results.insert(key.to_bytes_be(), value.to_bytes_be());
    }

    // store the results on chain
    Tally::insert::<&TopicId, BTreeMap<Plaintext, Count>>(topic_id, results.clone());
    Ok(results)
}
