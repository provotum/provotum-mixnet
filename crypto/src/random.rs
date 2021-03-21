use crate::{
    encryption::ElGamal,
    types::{Cipher, PublicKey},
};
use alloc::vec::Vec;
use core::ops::{AddAssign, Sub};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::Rng;
use std::boxed::Box;
use std::panic;

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub struct Random;

impl Random {
    pub fn generate_random_encryptions_encoded(
        pk: &PublicKey,
        q: &BigUint,
        number: usize,
    ) -> Vec<Cipher> {
        let mut encryptions: Vec<Cipher> = Vec::new();

        for i in 0..number {
            let nr = BigUint::from(i);
            let r = Random::get_random_less_than(q);
            let enc = ElGamal::encrypt_encode(&nr, &r, pk);
            encryptions.push(enc);
        }
        encryptions
    }

    /// used to suppress the panic message when using panic::catch_unwind
    fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(
        f: F,
    ) -> std::thread::Result<R> {
        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(f);
        panic::set_hook(prev_hook);
        result
    }

    pub fn generate_encryptions(
        pk: &PublicKey,
        q: &BigUint,
        number: usize,
        votes: Vec<u32>,
    ) -> Vec<Cipher> {
        assert!(!votes.is_empty(), "there must be at least one value!");
        let mut encryptions: Vec<Cipher> = Vec::new();

        'outer: loop {
            for vote in votes.iter() {
                // once sufficient encryptions have been generate
                // leave both loops
                if encryptions.len() == number {
                    break 'outer;
                }
                let r = Random::get_random_less_than(q);
                let nr = BigUint::from(*vote);
                let result = Self::catch_unwind_silent(|| ElGamal::encrypt(&nr, &r, pk));
                if result.is_ok() {
                    let enc = result.unwrap();
                    encryptions.push(enc.clone());
                }
            }
        }
        encryptions
    }

    pub fn generate_random_encryptions(pk: &PublicKey, q: &BigUint, number: usize) -> Vec<Cipher> {
        let mut encryptions: Vec<Cipher> = Vec::new();
        let mut i: u32 = 0;

        while encryptions.len() != number {
            let nr = BigUint::from(i);

            let r = Random::get_random_less_than(q);
            let result = Self::catch_unwind_silent(|| ElGamal::encrypt(&nr, &r, pk));
            if result.is_ok() {
                let enc = result.unwrap();
                encryptions.push(enc.clone());
            }
            i += 1u32;
        }
        encryptions
    }

    /// Shuffles a vector of encryptions (permuatation + re-encryption)
    ///
    /// Arguments
    /// * `pk` - public key
    /// * `q` - the group modulus
    /// * `encryptions` - a vector of encrypted votes
    pub fn generate_shuffle(
        pk: &PublicKey,
        q: &BigUint,
        encryptions: Vec<Cipher>,
    ) -> Vec<(Cipher, BigUint, usize)> {
        // create a permutation of size
        let size = encryptions.len();
        let permutation = Random::generate_permutation(&size);

        // create {size} random values < q
        let mut randoms: Vec<BigUint> = Vec::new();

        for _ in 0..size {
            randoms.push(Random::get_random_less_than(&q));
        }

        // shuffle (permute + re-encrypt) the encryptions
        ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
    }

    /// Generates a permutation of size: `size`
    ///
    /// Arguments
    /// * `size` - size of the permuatation
    pub fn generate_permutation(size: &usize) -> Vec<usize> {
        assert!(*size > 0, "size must be greater than zero!");

        let mut rng = rand::thread_rng();
        let mut permutation: Vec<usize> = Vec::new();

        // vector containing the range of values from 0 up to the size of the vector - 1
        let mut range: Vec<usize> = (0..*size).collect();

        for index in 0..*size {
            // get random integer
            let random = rng.gen_range(index, size);

            // get the element in the range at the random position
            let value = range.get(random);

            match value {
                Some(value) => {
                    // store the value of the element at the random position
                    permutation.push(*value);

                    // swap positions
                    range[random] = range[index];
                }
                None => panic!(
                    "Index out of bounds: index: {:?}, upper bound: {:?}",
                    random, size
                ),
            }
        }
        permutation
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

    /// Generates a random prime
    ///
    /// Arguments
    /// * `bit_size` - size of prime
    pub fn generate_random_prime(bit_size: u64) -> BigUint {
        let mut rng = rand::thread_rng();
        let mut candidate = rng.gen_biguint(bit_size);
        let two = BigUint::from(2u32);

        if &candidate % &two == BigUint::zero() {
            candidate.add_assign(BigUint::one())
        }

        while !Self::is_prime(&candidate, 128) {
            candidate.add_assign(two.clone());
        }
        candidate
    }

    /// Miller-Rabin Primality Test
    ///
    /// https://en.wikipedia.org/wiki/Miller-Rabin_primality_test
    pub fn is_prime(num: &BigUint, certainty: u32) -> bool {
        let zero: BigUint = BigUint::zero();
        let one: BigUint = BigUint::one();
        let two = one.clone() + one.clone();

        if *num == two {
            return true;
        }

        if num % two.clone() == zero {
            return false;
        }

        let num_less_one = num - one.clone();

        // write n-12**s * d
        let mut d = num_less_one.clone();
        let mut s: BigUint = Zero::zero();

        while d.clone() % two.clone() == zero.clone() {
            d /= two.clone();
            s += one.clone();
        }

        let mut k = 0;
        let mut rng = rand::thread_rng();

        // test for probable prime
        while k < certainty {
            let a = rng.gen_biguint_range(&two, num);
            let mut x = a.modpow(&d, num);
            if x != one.clone() && x != num_less_one {
                let mut random = zero.clone();
                loop {
                    x = x.modpow(&two, num);
                    if x == num_less_one {
                        break;
                    } else if x == one.clone() || random == (s.clone() - one.clone()) {
                        return false;
                    }
                    random += one.clone();
                }
            }
            k += 2;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::encryption::ElGamal;
    use crate::helper::Helper;
    use crate::random::Random;
    use num_bigint::BigUint;
    use std::vec::Vec;

    #[test]
    fn it_should_generate_random_number() {
        let number = BigUint::parse_bytes(b"123", 10).unwrap();
        for _ in 0..20 {
            let random = Random::get_random_less_than(&number);
            assert!(random < number);
        }
    }

    #[test]
    fn check_that_2_is_prime() {
        let number = BigUint::parse_bytes(b"2", 10).unwrap();
        let is_prime = Random::is_prime(&number, 20);
        assert!(is_prime);
    }

    #[test]
    fn check_that_11_is_prime() {
        let number = BigUint::from(11u32);
        let is_prime = Random::is_prime(&number, 20);
        assert!(is_prime);
    }

    #[test]
    fn check_that_84532559_is_prime() {
        let number = BigUint::parse_bytes(b"84532559", 10).unwrap();
        let is_prime = Random::is_prime(&number, 20);
        assert!(is_prime);
    }

    #[test]
    fn check_that_84532560_is_not_prime() {
        let number = BigUint::parse_bytes(b"84532560", 10).unwrap();
        let is_prime = Random::is_prime(&number, 20);
        assert!(!is_prime);
    }

    #[test]
    fn it_should_generate_a_random_prime() {
        let bit_size = 256;
        let byte_size = 32;

        let prime = Random::generate_random_prime(bit_size);

        // check that the prime is in range bit_size - 8 <= prime <= bit_size
        assert!(prime.bits().le(&bit_size));
        assert!(prime.bits().ge(&(bit_size - 8)));

        // check that the prime has the same number of bytes as requested
        assert!(prime.to_bytes_le().len() == byte_size);

        let is_prime = Random::is_prime(&prime, 128);
        assert!(is_prime);
    }

    #[test]
    #[should_panic(expected = "size must be greater than zero!")]
    fn permutation_size_zero_should_panic() {
        let size = 0;
        Random::generate_permutation(&size);
    }

    #[test]
    fn it_should_generate_a_permutation_for_three_numbers() {
        let size = 3;
        let permutation = Random::generate_permutation(&size);

        // check that the permutation has the expected size
        assert!(permutation.len() == (size as usize));

        // check that 0, 1, 2 occur at least once each
        assert!(permutation.iter().any(|&value| value == 0));
        assert!(permutation.iter().any(|&value| value == 1));
        assert!(permutation.iter().any(|&value| value == 2));
    }

    #[test]
    fn it_should_generate_a_random_encryptions_encoded() {
        let number = 2usize;
        let (params, _, pk) = Helper::setup_sm_system();
        let q = params.q();
        let encryptions = Random::generate_random_encryptions_encoded(&pk, &q, number);
        assert_eq!(encryptions.len(), number);
    }

    #[test]
    fn it_should_generate_a_random_encryptions() {
        let number = 2usize;
        let (params, _, pk) = Helper::setup_sm_system();
        let q = params.q();
        let encryptions = Random::generate_random_encryptions(&pk, &q, number);
        assert_eq!(encryptions.len(), number);
    }

    #[test]
    fn it_should_generate_an_encryption_of_one_and_two() {
        let votes = vec![1u32, 2u32];
        let number = 2usize;
        let (params, sk, pk) = Helper::setup_sm_system();
        let q = params.q();
        let encryptions = Random::generate_encryptions(&pk, &q, number, votes.clone());
        let decryptions = encryptions
            .iter()
            .map(|cipher| ElGamal::decrypt(cipher, &sk))
            .collect::<Vec<BigUint>>();

        // check that 1, 2 occur once each
        for vote in votes {
            assert!(decryptions
                .iter()
                .any(|value| value == &BigUint::from(vote)));
        }
        assert_eq!(decryptions.len(), number);
    }
}
