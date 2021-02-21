use crate::{Call, Error, Sealers, Trait};
use core::convert::TryInto;
use frame_support::{debug, storage::StorageValue};
use frame_system::offchain::{Account, SendSignedTransaction, Signer};
use sp_std::vec::Vec;

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

pub fn special<T: Trait>(
    block_number: T::BlockNumber,
    call: Call<T>,
) -> Result<(), Error<T>> {
    // get the signer for the transaction
    let signer = Signer::<T, T::AuthorityId>::any_account();

    // All `ImOnline` public (+private) keys currently in the local keystore.
    let result = signer.send_signed_transaction(|_acct| {
        debug::info!("account: {:?}", _acct.id);

        let sealers: Vec<T::AccountId> = Sealers::<T>::get();
        debug::info!("sealers: {:?}", sealers);

        debug::info!(
            "sealers contains addresss: {:?}",
            sealers.contains(&_acct.id)
        );

        // check who's turn it is
        let n: T::BlockNumber = (sealers.len() as u32).into();
        let index = block_number % n;

        let test = TryInto::<u64>::try_into(index).ok();
        let index_as_u64 = test.expect("Type conversion failed!");
        let sealer: &T::AccountId = &sealers[index_as_u64 as usize];
        debug::info!("it is sealer {:?} (index: {:?})", sealer, index);

        debug::info!(
            "is it the current sealer's turn: {:?}",
            sealer.eq(&_acct.id)
        );

        call.clone()
    });

    // display error if the signed tx fails.
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
