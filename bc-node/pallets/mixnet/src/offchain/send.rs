use crate::{Call, Error, Trait};
use frame_support::debug;
use frame_system::offchain::{SendSignedTransaction, Signer};

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
