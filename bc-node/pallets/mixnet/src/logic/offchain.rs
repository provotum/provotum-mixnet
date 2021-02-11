use crate::sp_api_hidden_includes_decl_storage::hidden_include::StorageMap;
use crate::types::{Ballot, Cipher, TopicId};
use crate::{Call, Error, Module, PublicKey, Trait, Votes};
use core::convert::TryInto;
use crypto::{encryption::ElGamal, types::PublicKey as ElGamalPK};
use frame_support::{debug, ensure};
use frame_system::offchain::{SendSignedTransaction, Signer};
use num_bigint::BigUint;
use sp_std::{vec, vec::Vec};

impl<T: Trait> Module<T> {
    pub fn offchain_signed_tx(
        block_number: T::BlockNumber,
        vote_id: Vec<u8>,
        topic_id: Vec<u8>,
    ) -> Result<(), Error<T>> {
        ensure!(
            Votes::<T>::contains_key(&vote_id),
            Error::<T>::VoteDoesNotExist
        );
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

    pub fn test() -> Result<(), Error<T>> {
        // We retrieve a signer and check if it is valid.
        // ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
        let accounts = Signer::<T, T::AuthorityId>::all_accounts();

        // debug::info!("count: {:#?}", accounts);

        Ok(())
    }

    // TODO: implement shuffle_ciphers -> used by offchain worker
    // TODO: implement generate_shuffle_proof -> used by offchain worker
    // TODO: implement creating a decrypted share + submitting it -> used by offchain worker
}
