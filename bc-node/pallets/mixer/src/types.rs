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
    pub g: Vec<u8>,
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
