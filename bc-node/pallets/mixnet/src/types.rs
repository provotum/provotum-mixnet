use crypto::types::{Cipher, ElGamalParams, PublicKey as ElGamalPK};
use frame_support::codec::{Decode, Encode};
use num_bigint::BigUint;
use num_traits::One;
use sp_std::vec::Vec;

/// the Cipher from the crypto crate.
/// different types which the blockchain can handle.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Ballot {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}

impl Into<Ballot> for Cipher {
    fn into(self) -> Ballot {
        Ballot {
            a: self.a.to_bytes_be(),
            b: self.b.to_bytes_be(),
        }
    }
}

impl Into<Cipher> for Ballot {
    fn into(self) -> Cipher {
        Cipher {
            a: BigUint::from_bytes_be(&self.a),
            b: BigUint::from_bytes_be(&self.b),
        }
    }
}

/// required to perform into() conversion for trait Vec
/// for Vec<Ballot> is not allowed, since trait Vec is not defined here
pub struct Wrapper<T>(pub Vec<T>);

impl Into<Vec<Cipher>> for Wrapper<Ballot> {
    fn into(self) -> Vec<Cipher> {
        self.0
            .into_iter()
            .map(|v| v.into())
            .collect::<Vec<Cipher>>()
    }
}

impl Into<Vec<Ballot>> for Wrapper<Cipher> {
    fn into(self) -> Vec<Ballot> {
        self.0
            .into_iter()
            .map(|v| v.into())
            .collect::<Vec<Ballot>>()
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
pub type BigS = (
    BigUint,      // s1
    BigUint,      // s2
    BigUint,      // s3
    BigUint,      // s4
    Vec<BigUint>, // vec_s_hat
    Vec<BigUint>, // vec_s_tilde
);

/// Algorithm 8.47: The ShuffleProof
pub type ShuffleProof = (
    BigUint,      // challenge
    BigS,         // S
    Vec<BigUint>, // permutation_commitments
    Vec<BigUint>, // permutation_chain_commitments
);
