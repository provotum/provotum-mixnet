use crate::helpers::assertions::ensure_vote_exists;
use crate::types::{Ballot, Cipher, TopicId, VoteId};
use crate::{Call, Error, Module, PublicKey, Sealers, Trait, VoteIds};
use core::convert::TryInto;
use crypto::{encryption::ElGamal, types::PublicKey as ElGamalPK};
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
        let pk: ElGamalPK = PublicKey::get(&vote_id)
            .ok_or(Error::<T>::PublicKeyNotExistsError)?
            .into();
        let q = &pk.params.q();

        // get a random value < q
        let r = Self::get_random_biguint_less_than(q)?;

        // encrypt the current block number
        let cipher: Cipher = ElGamal::encrypt_encode(&number_as_biguint, &r, &pk).into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id, cipher)];
        let ballot: Ballot = Ballot { answers };

        // `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
        //   - `None`: no account is available for sending transaction
        //   - `Some((account, Ok(())))`: transaction is successfully sent
        //   - `Some((account, Err(())))`: error occured when sending the transaction
        let result = signer.send_signed_transaction(|_acct| {
            Call::cast_ballot(vote_id.clone(), ballot.clone())
        });

        // Display error if the signed tx fails.
        if let Some((acc, res)) = result {
            if res.is_err() {
                debug::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
                return Err(<Error<T>>::OffchainSignedTxError);
            }
            // Transaction is sent successfully
            return Ok(());
        }

        // The case of `None`: no account is available for sending
        debug::error!("No local account available");
        Err(<Error<T>>::NoLocalAcctForSigning)
    }

    pub fn offchain_shuffle_and_proof(
        block_number: T::BlockNumber,
    ) -> Result<(), Error<T>> {
        if sp_io::offchain::is_validator() {
            debug::info!("hi there i'm a validator");

            let duration = T::BlockDuration::get();
            let zero: T::BlockNumber = 0u32.into();
            debug::info!("block duration: {:#?}", duration);

            let timestamp = sp_io::offchain::timestamp();
            debug::info!("timestamp: {:#?}", timestamp);

            let sealers: Vec<T::AccountId> = Sealers::<T>::get();
            debug::info!("sealers: {:#?}", sealers);

            // shuffle votes + create a proof
            if duration > zero && block_number % duration == zero {
                debug::info!("boss move");
            }

            // get all vote_ids
            let vote_ids: Vec<VoteId> = VoteIds::get();

            for vote_id in vote_ids {
                // ensure_vote_exists::<T>(&vote_id)?;
                debug::info!("vote_id: {:#?}", vote_id);
            }
        }

        // get the signer for the voter
        let signer = Signer::<T, T::AuthorityId>::any_account();

        Ok(())
    }

    // TODO: implement shuffle_ciphers -> used by offchain worker
    // TODO: implement generate_shuffle_proof -> used by offchain worker
    // TODO: implement creating a decrypted share + submitting it -> used by offchain worker
}
