use core::ops::Sub;
use crypto::{
    encryption::ElGamal,
    types::{Cipher as BigCipher, PublicKey as ElGamalPK},
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use std::panic;
use std::vec::Vec;

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub struct Random;

impl Random {
    pub fn get_random_encryptions(
        pk: &ElGamalPK,
        q: &BigUint,
        number: usize,
        encoded: bool,
    ) -> Vec<BigCipher> {
        if encoded {
            return Self::gen_rand_encryptions_encoded(pk, q, number);
        } else {
            return Self::gen_rand_encryptions(pk, q, number);
        }
    }

    fn gen_rand_encryptions_encoded(pk: &ElGamalPK, q: &BigUint, number: usize) -> Vec<BigCipher> {
        let mut encryptions: Vec<BigCipher> = Vec::new();

        for i in 0..number {
            let nr = BigUint::from(i);
            let r = Random::get_random_less_than(q);
            let enc = ElGamal::encrypt_encode(&nr, &r, pk);
            encryptions.push(enc);
        }
        encryptions
    }

    fn gen_rand_encryptions(pk: &ElGamalPK, q: &BigUint, number: usize) -> Vec<BigCipher> {
        let mut encryptions: Vec<BigCipher> = Vec::new();
        let mut i: u32 = 0;

        while encryptions.len() != number {
            let nr = BigUint::from(i);

            let r = Random::get_random_less_than(q);
            let result = panic::catch_unwind(|| ElGamal::encrypt(&nr, &r, pk));
            if result.is_ok() {
                let enc = result.unwrap();
                encryptions.push(enc.clone());
            }
            i += 1u32;
        }
        encryptions
    }

    /// Generates a random value: 0 < x < number
    ///
    /// Arguments
    /// * `number` - upper limit
    pub fn get_random_less_than(number: &BigUint) -> BigUint {
        assert!(*number > BigUint::zero(), "q must be greater than zero!");
        let one = BigUint::one();
        let upper_bound = number.clone().sub(one);
        let bit_size: u64 = upper_bound.bits();

        let mut rng = rand::thread_rng();
        rng.gen_biguint(bit_size) % number
    }
}

#[cfg(test)]
mod tests {
    use crate::random::Random;
    use num_bigint::BigUint;

    #[test]
    fn it_should_generate_random_number() {
        let number = BigUint::parse_bytes(b"123", 10).unwrap();
        for _ in 0..20 {
            let random = Random::get_random_less_than(&number);
            assert!(random < number);
        }
    }
}
