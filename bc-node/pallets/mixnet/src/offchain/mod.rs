mod send;

use crate::{
    helpers::{assertions::ensure_vote_exists, params::get_public_key},
    types::{
        Ballot, Cipher, PublicKey as SubstratePK, ShuffleProof, ShuffleProofAsBytes,
        Topic, TopicId, Vote, VoteId, VotePhase, Wrapper,
    },
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
    storage::{StorageDoubleMap, StorageMap, StorageValue},
    traits::Get,
};
use frame_system::offchain::{SendSignedTransaction, Signer};
use num_bigint::BigUint;
use send::send_signed;
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

    pub fn do_work_in_offchain_worker(
        block_number: T::BlockNumber,
    ) -> Result<(), Error<T>> {
        // if the offchain worker is not a validator, we don't shuffle the votes
        if !sp_io::offchain::is_validator() {
            return Ok(());
        }

        debug::info!("hi there i'm a validator");

        let duration = T::BlockDuration::get();
        let zero: T::BlockNumber = T::BlockNumber::from(0u32);
        debug::info!("block duration: {:?}", duration);

        let sealers: Vec<T::AccountId> = Sealers::<T>::get();
        debug::info!("sealers: {:?}", sealers);

        let voting_authorities: Vec<T::AccountId> = VotingAuthorities::<T>::get();
        debug::info!("voting_authorities: {:?}", voting_authorities);

        // // shuffle votes + create a proof
        // if duration > zero && block_number % duration == zero {
        //     debug::info!("boss move");
        // }

        // check who's turn it is
        let n: T::BlockNumber = (sealers.len() as u32).into();
        let index = block_number % n;

        let test = TryInto::<u64>::try_into(index).ok();
        let index_as_u64 = test.expect("Type conversion failed!");
        let sealer: &T::AccountId = &sealers[index_as_u64 as usize];
        debug::info!("it is sealer {:?} (index: {:?})", sealer, index);

        // get the signer for the transaction
        let signer = Signer::<T, T::AuthorityId>::any_account();

        // call send + return its result
        send_signed::<T>(signer, Call::test(true))
    }

    pub fn offchain_shuffle_and_proof(
        block_number: T::BlockNumber,
    ) -> Result<(), Error<T>> {
        // if the offchain worker is not a validator, we don't shuffle the votes
        if !sp_io::offchain::is_validator() {
            return Ok(());
        }

        // Only attempt to shuffle votes
        // every #BlockDuration of blocks
        let duration = T::BlockDuration::get();
        let zero: T::BlockNumber = T::BlockNumber::from(0u32);
        if block_number % duration != zero {
            return Ok(());
        }

        // get all vote_ids
        let vote_ids: Vec<VoteId> = VoteIds::get();
        debug::info!("vote_ids: {:?}", vote_ids);

        for vote_id in vote_ids.iter() {
            // check vote state -> TALLYING
            let vote: Vote<T::AccountId> = Votes::<T>::get(&vote_id);
            let state: VotePhase = vote.phase;

            // early return if the vote is not in
            if state != VotePhase::Tallying {
                continue;
            }

            debug::info!("vote_id: {:?}, state: VotePhase::Tallying", vote_id);

            // get all topics
            let topics: Vec<Topic> = Topics::get(vote_id);

            // get public key
            let pk: SubstratePK = get_public_key::<T>(&vote_id)?;
            let pk: ElGamalPK = pk.into();

            // TODO: figure out a way on how to decide what the current number of shuffles is
            let current_nr_of_shuffles: u8 = 0;

            for (topic_id, _) in topics.iter() {
                // get all encrypted votes (ciphers)
                // for the topic with id: topic_id and the # of shuffles (current_nr_of_shuffles)
                // TODO: implement a function to retrieve the most recent number of shuffles...
                debug::info!("topic_id: {:?}", topic_id);
                let ciphers: Vec<Cipher> =
                    Ciphers::get(&topic_id, current_nr_of_shuffles);

                // type conversion: Cipher (Vec<u8>) to BigCipher (BigUint)
                let encryptions: Vec<BigCipher> = Wrapper(ciphers).into();

                // for each topic_id & vote_id
                // shuffle the votes
                let (shuffled_encryptions, re_encryption_randoms, permutation): (
                    Vec<BigCipher>,
                    Vec<BigUint>,
                    Vec<usize>,
                ) = Self::shuffle_ciphers(pk.clone(), encryptions.clone())?;

                // generate the shuffle proof
                let proof: ShuffleProof = Self::generate_shuffle_proof(
                    &topic_id,
                    encryptions,
                    shuffled_encryptions.clone(),
                    re_encryption_randoms,
                    &permutation,
                    &pk,
                )?;

                // type conversions
                let shuffled_encryptions_as_bytes: Vec<Cipher> =
                    Wrapper(shuffled_encryptions).into();
                let proof_as_bytes: ShuffleProofAsBytes = proof.into();

                // get the signer for the transaction
                let signer = Signer::<T, T::AuthorityId>::any_account();

                // check who's turn it is
                let sealers: Vec<T::AccountId> = Sealers::<T>::get();
                let n: T::BlockNumber = (sealers.len() as u32).into();
                let index = block_number % n;
                let index_as_u64 = TryInto::<u64>::try_into(index)
                    .ok()
                    .expect("Type conversion failed!");
                let sealer: &T::AccountId = &sealers[index_as_u64 as usize];
                debug::info!("it is sealer {:?} (index: {:?})", sealer, index);

                // submit the shuffle proof and the shuffled ciphers
                let result = signer.send_signed_transaction(|_acct| {
                    debug::info!("account: {:?}", _acct.id);

                    let sealers: Vec<T::AccountId> = Sealers::<T>::get();
                    debug::info!("sealers: {:?}", sealers);

                    debug::info!(
                        "sealers contains addresss: {:?}",
                        sealers.contains(&_acct.id)
                    );

                    debug::info!(
                        "is it the current sealer's turn: {:?}",
                        sealer.eq(&_acct.id)
                    );

                    if sealer.eq(&_acct.id) {
                        Call::submit_shuffled_votes_and_proof(
                            vote_id.to_vec(),
                            topic_id.to_vec(),
                            proof_as_bytes.clone(),
                            shuffled_encryptions_as_bytes.clone(),
                            current_nr_of_shuffles,
                        )
                    } else {
                        Call::test(true)
                    }
                });

                // handle the response
                if let Some((acc, res)) = result {
                    // display error if the signed tx fails.
                    if res.is_err() {
                        debug::error!(
                            "failure in offchain tx, acc: {:?}, res: {:?}",
                            acc.id,
                            res
                        );
                    }
                    // Transaction is sent successfully
                    if sealer.eq(&acc.id) {
                        debug::info!(
                            "votes shuffled in offchain worker -> vote_id: {:?}",
                            vote_id
                        );
                    }
                } else {
                    // The case of `None`: no account is available for sending
                    debug::error!("No local account available");
                    return Err(<Error<T>>::NoLocalAcctForSigning);
                }
            }
        }
        Ok(())
    }
}

// TODO: implement creating a decrypted share + submitting it -> used by offchain worker
