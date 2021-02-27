use codec::{Decode, Encode};
use crypto::proofs::{decryption::DecryptionProof, keygen::KeyGenerationProof};
use crypto::types::{Cipher as BigCipher, ElGamalParams, PublicKey as ElGamalPK};
use frame_system::offchain::{SignedPayload, SigningTypes};
use num_bigint::BigUint;
use num_traits::One;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

/// the BigCipher from the crypto crate.
/// different types which the blockchain can handle.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Cipher {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}

impl Into<Cipher> for BigCipher {
    fn into(self) -> Cipher {
        Cipher {
            a: self.a.to_bytes_be(),
            b: self.b.to_bytes_be(),
        }
    }
}

impl Into<BigCipher> for Cipher {
    fn into(self) -> BigCipher {
        BigCipher {
            a: BigUint::from_bytes_be(&self.a),
            b: BigUint::from_bytes_be(&self.b),
        }
    }
}

/// required to perform into() conversion for trait Vec
/// for Vec<Cipher> is not allowed, since trait Vec is not defined here
pub struct Wrapper<T>(pub Vec<T>);

impl Into<Vec<BigCipher>> for Wrapper<Cipher> {
    fn into(self) -> Vec<BigCipher> {
        self.0
            .into_iter()
            .map(|v| v.into())
            .collect::<Vec<BigCipher>>()
    }
}

impl Into<Vec<Cipher>> for Wrapper<BigCipher> {
    fn into(self) -> Vec<Cipher> {
        self.0
            .into_iter()
            .map(|v| v.into())
            .collect::<Vec<Cipher>>()
    }
}

/// the PublicKey from the crypto crate.
/// different types which the blockchain can handle.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    pub params: PublicParameters,
    pub h: Vec<u8>,
}

impl Into<PublicKey> for ElGamalPK {
    fn into(self) -> PublicKey {
        PublicKey {
            params: self.params.into(),
            h: self.h.to_bytes_be(),
        }
    }
}

impl Into<ElGamalPK> for PublicKey {
    fn into(self) -> ElGamalPK {
        ElGamalPK {
            params: self.params.into(),
            h: BigUint::from_bytes_be(&self.h),
        }
    }
}

/// the ElGamalParams from the crypto crate.
/// different types which the blockchain can handle.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct PublicParameters {
    pub p: Vec<u8>,
    // 1. public generator g
    pub g: Vec<u8>,
    // 2. public generator h
    pub h: Vec<u8>,
}

/// defines the function q = (p - 1) / 2 with return type BigUint.
/// implemented for PublicParameters (i.e. ElGamalParams from the crypto crate)
pub trait QAsBigUint {
    fn q(&self) -> BigUint;
}

impl QAsBigUint for PublicParameters {
    fn q(&self) -> BigUint {
        let p: BigUint = BigUint::from_bytes_be(&self.p);
        let q: BigUint = (p - BigUint::one()) / BigUint::from(2u32);
        q
    }
}

/// defines the function q = (p - 1) / 2 with return type Vec<u8>
/// implemented for PublicParameters (i.e. ElGamalParams from the crypto crate)
pub trait QAsVecU8 {
    fn q(&self) -> Vec<u8>;
}

impl QAsVecU8 for PublicParameters {
    fn q(&self) -> Vec<u8> {
        let p: BigUint = BigUint::from_bytes_be(&self.p);
        let q: BigUint = (p - BigUint::one()) / BigUint::from(2u32);
        q.to_bytes_be()
    }
}

impl Into<PublicParameters> for ElGamalParams {
    fn into(self) -> PublicParameters {
        PublicParameters {
            p: self.p.to_bytes_be(),
            g: self.g.to_bytes_be(),
            h: self.h.to_bytes_be(),
        }
    }
}

impl Into<ElGamalParams> for PublicParameters {
    fn into(self) -> ElGamalParams {
        ElGamalParams {
            p: BigUint::from_bytes_be(&self.p),
            g: BigUint::from_bytes_be(&self.g),
            h: BigUint::from_bytes_be(&self.h),
        }
    }
}

/// Algorithm 8.47: The s value of the ShuffleProof
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct BigS {
    pub s1: BigUint,               // s1
    pub s2: BigUint,               // s2
    pub s3: BigUint,               // s3
    pub s4: BigUint,               // s4
    pub vec_s_hat: Vec<BigUint>,   // vec_s_hat
    pub vec_s_tilde: Vec<BigUint>, // vec_s_tilde
}

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct BigSAsBytes {
    pub s1: Vec<u8>,               // s1
    pub s2: Vec<u8>,               // s2
    pub s3: Vec<u8>,               // s3
    pub s4: Vec<u8>,               // s4
    pub vec_s_hat: Vec<Vec<u8>>,   // vec_s_hat
    pub vec_s_tilde: Vec<Vec<u8>>, // vec_s_tilde
}

impl Into<BigS> for BigSAsBytes {
    fn into(self) -> BigS {
        BigS {
            s1: BigUint::from_bytes_be(&self.s1),
            s2: BigUint::from_bytes_be(&self.s2),
            s3: BigUint::from_bytes_be(&self.s3),
            s4: BigUint::from_bytes_be(&self.s4),
            vec_s_hat: self
                .vec_s_hat
                .iter()
                .map(|v| BigUint::from_bytes_be(v))
                .collect::<Vec<BigUint>>(),
            vec_s_tilde: self
                .vec_s_tilde
                .iter()
                .map(|v| BigUint::from_bytes_be(v))
                .collect::<Vec<BigUint>>(),
        }
    }
}

impl Into<BigSAsBytes> for BigS {
    fn into(self) -> BigSAsBytes {
        BigSAsBytes {
            s1: self.s1.to_bytes_be(),
            s2: self.s2.to_bytes_be(),
            s3: self.s3.to_bytes_be(),
            s4: self.s4.to_bytes_be(),
            vec_s_hat: self
                .vec_s_hat
                .into_iter()
                .map(|v| v.to_bytes_be())
                .collect::<Vec<Vec<u8>>>(),
            vec_s_tilde: self
                .vec_s_tilde
                .into_iter()
                .map(|v| v.to_bytes_be())
                .collect::<Vec<Vec<u8>>>(),
        }
    }
}

/// Algorithm 8.47: The ShuffleProof
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct ShuffleProof {
    pub challenge: BigUint,                          // challenge
    pub S: BigS,                                     // S
    pub permutation_commitments: Vec<BigUint>,       // permutation_commitments
    pub permutation_chain_commitments: Vec<BigUint>, // permutation_chain_commitments
}

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct ShuffleProofAsBytes {
    pub challenge: Vec<u8>,                          // challenge
    pub S: BigSAsBytes,                              // S
    pub permutation_commitments: Vec<Vec<u8>>,       // permutation_commitments
    pub permutation_chain_commitments: Vec<Vec<u8>>, // permutation_chain_commitments
}

impl Into<ShuffleProof> for ShuffleProofAsBytes {
    fn into(self) -> ShuffleProof {
        ShuffleProof {
            challenge: BigUint::from_bytes_be(&self.challenge),
            S: self.S.into(),
            permutation_commitments: self
                .permutation_commitments
                .iter()
                .map(|v| BigUint::from_bytes_be(v))
                .collect::<Vec<BigUint>>(),
            permutation_chain_commitments: self
                .permutation_chain_commitments
                .iter()
                .map(|v| BigUint::from_bytes_be(v))
                .collect::<Vec<BigUint>>(),
        }
    }
}

impl Into<ShuffleProofAsBytes> for ShuffleProof {
    fn into(self) -> ShuffleProofAsBytes {
        ShuffleProofAsBytes {
            challenge: self.challenge.to_bytes_be(),
            S: self.S.into(),
            permutation_commitments: self
                .permutation_commitments
                .into_iter()
                .map(|v| v.to_bytes_be())
                .collect::<Vec<Vec<u8>>>(),
            permutation_chain_commitments: self
                .permutation_chain_commitments
                .into_iter()
                .map(|v| v.to_bytes_be())
                .collect::<Vec<Vec<u8>>>(),
        }
    }
}

// the payload submitted after performing a shuffle proof in an offchain worker
// contains the shuffle proof and the shuffle_votes
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct ShufflePayload {
    pub iteration: u8,
    pub ciphers: Vec<Cipher>,
    pub proof: ShuffleProofAsBytes,
}

pub type VoteId = Vec<u8>;
pub type Title = Vec<u8>;

// both types are strings encoded as bytes
pub type NrOfShuffles = u8;
pub type TopicId = Vec<u8>;
pub type TopicQuestion = Vec<u8>;

// result types
pub type Plaintext = Vec<u8>;
pub type Count = Vec<u8>;

// topicId and question (string as Vec<u8>)
pub type Topic = (TopicId, TopicQuestion);

/// A ballot is composed of all answers of a voter
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Ballot {
    pub answers: Vec<(TopicId, Cipher)>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub enum VotePhase {
    KeyGeneration,
    Voting,
    Tallying,
}

// Default defines the starting value when VotePhase is created
impl Default for VotePhase {
    fn default() -> Self {
        Self::KeyGeneration
    }
}

/// A vote groups the voting authority, the title of the vote,
/// the phase the vote is currently in and the public parameters
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Vote<AccountId> {
    pub voting_authority: AccountId,
    pub title: Title,
    pub phase: VotePhase,
    pub params: PublicParameters,
}

// the public key generation proof submitted by the sealer -> this prooves knowledge of a secret key that belongs to the submitted public key
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct PublicKeyShareProof {
    pub challenge: Vec<u8>,
    pub response: Vec<u8>,
}

impl Into<PublicKeyShareProof> for KeyGenerationProof {
    fn into(self) -> PublicKeyShareProof {
        PublicKeyShareProof {
            challenge: self.challenge.to_bytes_be(),
            response: self.response.to_bytes_be(),
        }
    }
}

impl Into<KeyGenerationProof> for PublicKeyShareProof {
    fn into(self) -> KeyGenerationProof {
        KeyGenerationProof {
            challenge: BigUint::from_bytes_be(&self.challenge),
            response: BigUint::from_bytes_be(&self.response),
        }
    }
}

// the public key share submitted by each sealer to generated the system's public key
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct PublicKeyShare {
    pub pk: Vec<u8>,
    pub proof: PublicKeyShareProof,
}

pub type DecryptedShare = Vec<u8>;

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct DecryptedShareProof {
    pub challenge: Vec<u8>,
    pub response: Vec<u8>,
}

impl From<DecryptionProof> for DecryptedShareProof {
    fn from(source: DecryptionProof) -> Self {
        DecryptedShareProof {
            challenge: source.challenge.to_bytes_be(),
            response: source.response.to_bytes_be(),
        }
    }
}

impl From<DecryptedShareProof> for DecryptionProof {
    fn from(source: DecryptedShareProof) -> Self {
        DecryptionProof {
            challenge: BigUint::from_bytes_be(&source.challenge),
            response: BigUint::from_bytes_be(&source.response),
        }
    }
}

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
