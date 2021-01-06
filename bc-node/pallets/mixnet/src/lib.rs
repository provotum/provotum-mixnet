#![cfg_attr(not(feature = "std"), no_std)]
#![feature(unsized_locals)]
extern crate alloc;

#[allow(clippy::many_single_char_names)]
mod helpers;

#[allow(clippy::many_single_char_names)]
mod logic;

#[allow(clippy::many_single_char_names)]
mod shuffle;

#[allow(clippy::many_single_char_names)]
pub mod types;

mod bench;

#[cfg(test)]
mod mock;

#[cfg(test)]
#[macro_use]
mod tests;

pub mod keys;

use codec::{Decode, Encode};
use frame_support::{
    debug, decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
    weights::Pays,
};
use frame_system::{
    self as system, ensure_signed,
    offchain::{AppCrypto, CreateSignedTransaction, SignedPayload, SigningTypes},
};
use num_bigint::BigUint;
use num_traits::One;
use sp_runtime::{offchain as rt_offchain, RuntimeDebug};
use sp_std::{prelude::*, str, vec::Vec};
use types::{
    Ballot, Cipher, PublicKey as SubstratePK, PublicParameters, Title, Topic, TopicId, Vote,
    VoteId, VotePhase,
};

/// the type to sign and send transactions.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Payload<Public> {
    ballot: Ballot,
    public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

/// This is the pallet's configuration trait
pub trait Trait: system::Trait + CreateSignedTransaction<Call<Self>> {
    /// The identifier type for an offchain worker.
    type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
    /// The overarching dispatch call type.
    type Call: From<Call<Self>>;
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as OffchainModule {
        pub VotingAuthorities get(fn voting_authorities) config(): Vec<T::AccountId>;
        pub Sealers get(fn sealers) config(): Vec<T::AccountId>;

        /// A vector containing the IDs of voters that have submitted their ballots
        Voters get(fn voters): Vec<T::AccountId>;

        /// Set of all voteIds
        VoteIds get(fn vote_ids): Vec<VoteId>;

        /// Maps a vote (i.e. the voteId) to a due date
        Votes get(fn votes): map hasher(blake2_128_concat) VoteId => Vote<T::AccountId>;

        /// Maps a voteId to a topic (topicId, question)
        Topics get(fn topics): map hasher(blake2_128_concat) VoteId => Vec<Topic>;

        /// Maps an voter and a vote to a ballot. Used to verify if a voter has already voted.
        Ballots get(fn ballots): double_map hasher(blake2_128_concat) VoteId, hasher(blake2_128_concat) T::AccountId => Ballot;

        /// Maps a topicId (question) to a list of Ciphers
        Ciphers get(fn ciphers): map hasher(blake2_128_concat) TopicId => Vec<Cipher>;

        /// The system's public key
        PublicKey get(fn public_key): Option<SubstratePK>;
    }
}

decl_event!(
    /// Events generated by the module.
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        /// ballot submission event -> [from/who, ballot]
        BallotSubmitted(AccountId, VoteId, Ballot),

        /// public key stored event -> [from/who, public key]
        PublicKeyStored(AccountId, SubstratePK),

        /// A voting authority set the vote's public parameters. [vote, who, params]
        VoteCreatedWithPublicParameters(VoteId, AccountId, PublicParameters),

        /// A voting authority set the question of a topic of a vote [vote, (topic_id, question)]
        VoteTopicQuestionStored(VoteId, Topic),
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        // Error returned when not sure which off-chain worker function to executed
        UnknownOffchainMux,

        // Error returned when Vec<u8> cannot be parsed into BigUint
        ParseError,

        // Error returned when requester is not a voting authority
        NotAVotingAuthority,

        // Error returned when making signed transactions in off-chain worker
        NoLocalAcctForSigning,
        OffchainSignedTxError,

        // Error returned when failing to get randomness
        RandomnessGenerationError,

        // Error returned when upper bound is zero
        RandomnessUpperBoundZeroError,

        // Error returned when error occurs in gen_random_range
        RandomRangeError,

        // Error returned when permutation size is zero
        PermutationSizeZeroError,

        // Error returned when ballots are empty when trying to shuffle them
        ShuffleCiphersSizeZeroError,

        // Error returned when public key doesn't exist
        PublicKeyNotExistsError,

        // Error returned when inverse modulo operation fails
        InvModError,

        // Error returned when division modulo operation fails
        DivModError,

        // Error returned when vote_id does not exist yet
        VoteDoesNotExist,
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Errors must be initialized if they are used by the pallet.
        type Error = Error<T>;

        // Events must be initialized if they are used by the pallet.
        fn deposit_event() = default;

        #[weight = (10000, Pays::No)]
        pub fn store_public_key(origin, pk: SubstratePK) -> DispatchResult {
          // check that the extrinsic was signed and get the signer.
          let who = ensure_signed(origin)?;

          // store the public key
          PublicKey::put(pk.clone());

          // notify that the public key has been successfully stored
          Self::deposit_event(RawEvent::PublicKeyStored(who, pk));

          // Return a successful DispatchResult
          Ok(())
        }

        /// Create a vote and store public crypto parameters.
        /// Can only be called from a voting authority.
        #[weight = (10000, Pays::No)]
        fn create_vote(origin, vote_id: Vec<u8>, title: Title, params: PublicParameters, topics: Vec<Topic>) -> DispatchResult {
            let who: T::AccountId = ensure_signed(origin)?;

            // only the voting_authority should be able to create a vote
            helpers::assertions::ensure_voting_authority::<T>(&who)?;

            let vote = Vote::<T::AccountId> {
                voting_authority: who.clone(),
                title: title.clone(),
                phase: VotePhase::default(),
                params: params.clone()
            };

            let mut vote_ids: Vec<VoteId> = VoteIds::get();
            vote_ids.push(vote_id.clone());
            VoteIds::put(vote_ids);

            Votes::<T>::insert(&vote_id, vote);
            Topics::insert(&vote_id, topics);

            Self::deposit_event(RawEvent::VoteCreatedWithPublicParameters(vote_id, who.clone(), params));

            // Return a successful DispatchResult
            Ok(())
        }

        /// Add a question to the vote.
        /// Can only be called from a voting authority.
        #[weight = (10000, Pays::No)]
        fn store_question(origin, vote_id: VoteId, topic: Topic) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // only the voting_authority should be able to set the question
            helpers::assertions::ensure_voting_authority::<T>(&who)?;

            // check that the vote_id exists
            ensure!(Votes::<T>::contains_key(&vote_id), Error::<T>::VoteDoesNotExist);

            let mut topics: Vec<Topic> = Topics::get(&vote_id);
            topics.push(topic.clone());
            Topics::insert(&vote_id, topics);

            Self::deposit_event(RawEvent::VoteTopicQuestionStored(vote_id, topic));

            // Return a successful DispatchResult
            Ok(())
        }

        #[weight = (10000, Pays::No)]
        pub fn cast_ballot(origin, vote_id: VoteId, ballot: Ballot) -> DispatchResult {
          // check that the extrinsic was signed and get the signer.
          let who = ensure_signed(origin)?;

          // check that the vote_id exists
          ensure!(Votes::<T>::contains_key(&vote_id), Error::<T>::VoteDoesNotExist);

          // store the ballot
          Self::store_ballot(&who, &vote_id, ballot.clone());

          // notify that the ballot has been submitted and successfully stored
          Self::deposit_event(RawEvent::BallotSubmitted(who, vote_id, ballot));

          // Return a successful DispatchResult
          Ok(())
        }

        fn offchain_worker(block_number: T::BlockNumber) {
            debug::info!("off-chain worker: entering...");

            // Only send messages if we are a potential validator.
            if sp_io::offchain::is_validator() {
                debug::info!("hi there i'm a validator");
            }

            let number: BigUint = BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
            let random = Self::get_random_biguint_less_than(&number);
            match random {
                Ok(value) => debug::info!(
                    "off-chain worker: random value: {:?} less than: {:?}",
                    value,
                    number
                ),
                Err(error) => debug::error!("off-chain worker - error: {:?}", error),
            }

            let lower: BigUint = BigUint::one();
            let value = Self::get_random_bigunint_range(&lower, &number);
            match value {
                Ok(val) => debug::info!("off-chain worker: random bigunit value in range. lower: {:?}, upper: {:?}, value: {:?}", lower, number, val),
                Err(error) => debug::error!("off-chain worker - error: {:?}", error),
            }

            let value = Self::get_random_range(5, 12312356);
            match value {
                Ok(val) => debug::info!(
                    "off-chain worker: random value in range. lower: {:?}, upper: {:?}, value: {:?}",
                    5,
                    12312356,
                    val
                ),
                Err(error) => debug::error!("off-chain worker - error: {:?}", error),
            }

            let value = Self::generate_permutation(10);
            match value {
                Ok(val) => debug::info!("off-chain worker: permutation: {:?}", val),
                Err(error) => debug::error!("off-chain worker - error: {:?}", error),
            }

            debug::info!("off-chain worker: done...");
        }
    }
}

impl<T: Trait> rt_offchain::storage_lock::BlockNumberProvider for Module<T> {
    type BlockNumber = T::BlockNumber;
    fn current_block_number() -> Self::BlockNumber {
        <frame_system::Module<T>>::block_number()
    }
}