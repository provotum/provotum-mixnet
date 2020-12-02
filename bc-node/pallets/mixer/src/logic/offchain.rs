use crate::sp_api_hidden_includes_decl_storage::hidden_include::StorageValue;
use crate::types::Ballot;
use crate::{Call, Error, Module, PublicKey, Trait};
use core::convert::TryInto;
use crypto::{encryption::ElGamal, types::PublicKey as ElGamalPK};
use frame_support::debug;
use frame_system::offchain::{SendSignedTransaction, Signer};
use num_bigint::BigUint;

impl<T: Trait> Module<T> {
    pub fn offchain_signed_tx(block_number: T::BlockNumber) -> Result<(), Error<T>> {
        // We retrieve a signer and check if it is valid.
        // ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
        let signer = Signer::<T, T::AuthorityId>::any_account();

        // translating the current block number to number and submit it on-chain
        let number: u64 = block_number.try_into().unwrap_or(0) as u64;

        // transform u64 to BigUint
        let number_as_biguint: BigUint = BigUint::from(number);

        // get public key
        let pk: ElGamalPK = PublicKey::get()
            .ok_or(Error::<T>::PublicKeyNotExistsError)?
            .into();
        let q = &pk.params.q();

        // get a random value < q
        let r = Self::get_random_biguint_less_than(q)?;

        // encrypt the current block number
        let ballot: Ballot = ElGamal::encrypt(&number_as_biguint, &r, &pk).into();

        // `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
        //   - `None`: no account is available for sending transaction
        //   - `Some((account, Ok(())))`: transaction is successfully sent
        //   - `Some((account, Err(())))`: error occured when sending the transaction
        let result = signer.send_signed_transaction(|_acct|
    // This is the on-chain function
          Call::cast_ballot(ballot.clone()));

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
}
