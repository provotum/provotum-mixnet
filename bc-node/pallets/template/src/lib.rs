#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{
    codec::Encode, debug, decl_error, decl_event, decl_module, decl_storage, dispatch, traits::Get,
    weights::Pays,
};
use frame_system::ensure_signed;
use sp_std::if_std;
use sp_std::vec::Vec;

use crate::types::Ballot;

mod types;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Trait: frame_system::Trait {
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

// The pallet's runtime storage items.
decl_storage! {
    // TODO: update name TemplateModule
    trait Store for Module<T: Trait> as TemplateModule {
        Something get(fn something): Option<u32>;
        Ballots get(fn ballots): Vec<Ballot>;
        Voters get(fn voters): Vec<T::AccountId>;
    }
}

// Pallets use events to inform users when important changes are made.
decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as frame_system::Trait>::AccountId,
    {
        /// Event documentation should end with an array that provides descriptive names for event
        /// parameters. [something, who]
        SomethingStored(u32, AccountId),

        /// vote submission event -> [from/who, encrypted vote]
        VoteSubmitted(AccountId, Ballot),
    }
);

// Errors inform users that something went wrong.
decl_error! {
    pub enum Error for Module<T: Trait> {
        /// Error names should be descriptive.
        NoneValue,
        /// Errors should have helpful documentation associated with them.
        StorageOverflow,
    }
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Errors must be initialized if they are used by the pallet.
        type Error = Error<T>;

        // Events must be initialized if they are used by the pallet.
        fn deposit_event() = default;

        /// An example dispatchable that takes a singles value as a parameter, writes the value to
        /// storage and emits an event. This function must be dispatched by a signed extrinsic.
        #[weight = 10_000 + T::DbWeight::get().writes(1)]
        pub fn do_something(origin, something: u32) -> dispatch::DispatchResult {
            // Check that the extrinsic was signed and get the signer.
            // This function will return an error if the extrinsic is not signed.
            // https://substrate.dev/docs/en/knowledgebase/runtime/origin
            let who = ensure_signed(origin)?;

            // Update storage.
            Something::put(something);

            // Emit an event.
            Self::deposit_event(RawEvent::SomethingStored(something, who));
            // Return a successful DispatchResult
            Ok(())
        }

        /// An example dispatchable that may throw a custom error.
        #[weight = 10_000 + T::DbWeight::get().reads_writes(1,1)]
        pub fn cause_error(origin) -> dispatch::DispatchResult {
            let _who = ensure_signed(origin)?;

            // Read a value from storage.
            match Something::get() {
                // Return an error if the value has not been set.
                None => Err(Error::<T>::NoneValue)?,
                Some(old) => {
                    // Increment the value read from storage; will error in the event of overflow.
                    let new = old.checked_add(1).ok_or(Error::<T>::StorageOverflow)?;
                    // Update the value in storage with the incremented result.
                    Something::put(new);
                    Ok(())
                },
            }
        }

        #[weight = (10000, Pays::No)]
        fn cast_encrypted_ballot(origin, vote: Ballot) -> dispatch::DispatchResult {
            // check that the extrinsic was signed and get the signer.
            let who = ensure_signed(origin)?;
            let address_bytes = who.encode();
            debug::info!("Voter {:?} (encoded: {:?}) cast a vote.", &who, address_bytes);

            if_std! {
                // This code is only being compiled and executed when the `std` feature is enabled.
                println!("Voter {:?} (encoded: {:?}) cast a vote.", &who, address_bytes);
            }

            // store the vote
            Self::store_encrypted_ballot(who.clone(), vote.clone());

            // notify that the vote has been submitted and successfully stored
            Self::deposit_event(RawEvent::VoteSubmitted(who, vote));

            // Return a successful DispatchResult
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    fn store_encrypted_ballot(from: T::AccountId, vote: Ballot) {
        // store the vote
        let mut ballots: Vec<Ballot> = Ballots::get();
        ballots.push(vote.clone());
        Ballots::put(ballots);
        debug::info!("Encrypted Ballot: {:?} has been stored.", vote);

        if_std! {
            // This code is only being compiled and executed when the `std` feature is enabled.
            println!("Encrypted Ballot: {:?} has been stored.", vote);
        }

        // update the list of voters
        let mut voters: Vec<T::AccountId> = Voters::<T>::get();
        voters.push(from.clone());
        Voters::<T>::put(voters);
        debug::info!("Voter {:?} has been stored.", from);

        if_std! {
            // This code is only being compiled and executed when the `std` feature is enabled.
            println!("Voter {:?} has been stored.", from);
        }
    }
}
