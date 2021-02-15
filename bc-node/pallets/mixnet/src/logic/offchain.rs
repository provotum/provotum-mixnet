use crate::{
    helpers::{assertions::ensure_vote_exists, keys::get_public_key},
    types::{Ballot, Cipher, Topic, TopicId, Vote, VoteId, VotePhase, Wrapper},
};
use crate::{
    Call, Ciphers, Error, Module, Sealers, Topics, Trait, VoteIds, Votes,
    VotingAuthorities,
};
use core::convert::TryInto;
use crypto::{
    encryption::ElGamal, types::Cipher as BigCipher, types::PublicKey as ElGamalPK,
};
use frame_support::{
    debug,
    storage::{StorageMap, StorageValue},
    traits::Get,
};
use frame_system::offchain::{SendSignedTransaction, Signer};
use num_bigint::BigUint;
use sp_std::{vec, vec::Vec};

impl<T: Trait> Module<T> {
    pub fn offchain_signed_tx(
        block_number: T::BlockNumber,
        vote_id: Vec<u8>,
        topic_id: Vec<u8>,
    ) -> Result<(), Error<T>> {
        ensure_vote_exists::<T>(&vote_id)?;

        // We retrieve a signer and check if it is valid.
        // ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
        let signer = Signer::<T, T::AuthorityId>::any_account();

        // translating the current block number to number and submit it on-chain
        let number: u64 = block_number.try_into().unwrap_or(0u64) as u64;

        // transform u64 to BigUint
        let number_as_biguint: BigUint = BigUint::from(number);

        // get public key
        let pk: ElGamalPK = get_public_key::<T>(&vote_id)?.into();
        let q = &pk.params.q();

        // get a random value < q
        let r = Self::get_random_biguint_less_than(q)?;

        // encrypt the current block number
        let cipher: Cipher = ElGamal::encrypt_encode(&number_as_biguint, &r, &pk).into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id, cipher)];
        let ballot: Ballot = Ballot { answers };

        return send_signed::<T>(
            signer,
            Call::cast_ballot(vote_id.clone(), ballot.clone()),
        );
    }

    pub fn block_number_to_u64(input: T::BlockNumber) -> Option<u64> {
        TryInto::<u64>::try_into(input).ok()
    }

    pub fn do_work_in_offchain_worker(
        block_number: T::BlockNumber,
    ) -> Result<(), Error<T>> {
        if sp_io::offchain::is_validator() {
            debug::info!("hi there i'm a validator");

            let duration = T::BlockDuration::get();
            let zero: T::BlockNumber = T::BlockNumber::from(0u32);
            debug::info!("block duration: {:#?}", duration);

            let timestamp = sp_io::offchain::timestamp();
            debug::info!("timestamp: {:#?}", timestamp);

            let sealers: Vec<T::AccountId> = Sealers::<T>::get();
            debug::info!("sealers: {:#?}", sealers);

            let voting_authorities: Vec<T::AccountId> = VotingAuthorities::<T>::get();
            debug::info!("voting_authorities: {:#?}", voting_authorities);

            // shuffle votes + create a proof
            if duration > zero && block_number % duration == zero {
                debug::info!("boss move");
            }

            // check who's turn it is
            let n: T::BlockNumber = (sealers.len() as u32).into();
            let index = block_number % n;

            let test = Self::block_number_to_u64(index);
            let index_as_u64 = test.expect("Type conversion failed!");
            let sealer: &T::AccountId = &sealers[index_as_u64 as usize];
            debug::info!("it is sealer {:#?} (index: {:#?})", sealer, index);

            // get the signer for the voter
            let signer = Signer::<T, T::AuthorityId>::any_account();

            // creat the shuffle
            let result_ = Self::offchain_shuffle_and_proof()?;

            // call send + return its result
            return send_signed::<T>(signer, Call::test(true));
        }
        Ok(())
    }

    fn offchain_shuffle_and_proof() -> Result<(), Error<T>> {
        // get all vote_ids
        let vote_ids: Vec<VoteId> = VoteIds::get();

        for vote_id in vote_ids.iter() {
            debug::info!("vote_id: {:#?}", vote_id);

            // check vote state -> TALLYING
            let vote: Vote<T::AccountId> = Votes::<T>::get(&vote_id);
            let state: VotePhase = vote.phase;

            if state == VotePhase::Tallying {
                // get all topics
                let topics: Vec<Topic> = Topics::get(vote_id);

                // get public key
                let pk: ElGamalPK = get_public_key::<T>(&vote_id)?.into();

                for (topic_id, _) in topics.iter() {
                    // for each topic_id & vote_id
                    // shuffle the votes
                    let (shuffled_encryptions, re_encryption_randoms, permutation): (
                        Vec<BigCipher>,
                        Vec<BigUint>,
                        Vec<usize>,
                    ) = Self::shuffle_ciphers(vote_id, topic_id)?;

                    // fetch the original votes
                    let encryptions: Vec<Cipher> = Ciphers::get(topic_id);
                    // type conversion: Ballot (Vec<u8>) to BigCipher (BigUint)
                    let encryptions: Vec<BigCipher> = Wrapper(encryptions).into();

                    // generate the shuffle proof
                    let proof = Self::generate_shuffle_proof(
                        &topic_id,
                        encryptions,
                        shuffled_encryptions,
                        re_encryption_randoms,
                        &permutation,
                        &pk,
                    )?;

                    // TODO: call extrinsic to verify shuffle proof
                    // let response = send_signed::<T>(signer, Call::verify_shuffle_proof)
                }
            }
        }
        Ok(())
    }

    // TODO: implement shuffle_ciphers -> used by offchain worker
    // TODO: implement generate_shuffle_proof -> used by offchain worker
}

pub fn send_signed<T: Trait>(
    signer: Signer<T, T::AuthorityId>,
    call: Call<T>,
) -> Result<(), Error<T>> {
    // `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
    //   - `None`: no account is available for sending transaction
    //   - `Some((account, Ok(())))`: transaction is successfully sent
    //   - `Some((account, Err(())))`: error occured when sending the transaction
    let result = signer.send_signed_transaction(|_acct| call.clone());

    // display error if the signed tx fails.
    if let Some((acc, res)) = result {
        if res.is_err() {
            debug::error!("failure: offchain_signed_tx: tx sent: {:#?}", acc.id);
            return Err(<Error<T>>::OffchainSignedTxError);
        }
        // Transaction is sent successfully
        return Ok(());
    }

    // The case of `None`: no account is available for sending
    debug::error!("No local account available");
    return Err(<Error<T>>::NoLocalAcctForSigning);
}

// TODO: implement creating a decrypted share + submitting it -> used by offchain worker
