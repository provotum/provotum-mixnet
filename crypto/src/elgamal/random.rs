use core::ops::{AddAssign, Sub};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};

pub struct Random;

impl Random {
    // generate a random value: 0 < x < number
    pub fn random_lt_number(number: &BigUint) -> BigUint {
        assert!(*number > BigUint::zero(), "q must be greater than zero!");
        let one = BigUint::one();
        let upper_bound = number.clone().sub(one);
        let bit_size: u64 = upper_bound.bits();

        let mut rng = rand::thread_rng();
        rng.gen_biguint(bit_size) % number
    }

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

    // Miller-Rabin Primality Test
    // https://en.wikipedia.org/wiki/Miller-Rabin_primality_test
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
                let mut r = zero.clone();
                loop {
                    x = x.modpow(&two, num);
                    if x == num_less_one {
                        break;
                    } else if x == one.clone() || r == (s.clone() - one.clone()) {
                        return false;
                    }
                    r += one.clone();
                }
            }
            k += 2;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::random::Random;
    use num_bigint::BigUint;

    #[test]
    fn it_should_generate_random_number() {
        let number = BigUint::parse_bytes(b"123", 10).unwrap();
        for _ in 0..20 {
            let random = Random::random_lt_number(&number);
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
    fn should_generate_random_prime() {
        let bit_size = 256;
        let byte_size = 32;

        let prime = Random::generate_random_prime(bit_size);

        // check that the prime is in range bit_size - 8 <= prime <= bit_size
        assert!(prime.bits().le(&bit_size));
        assert!(prime.bits().ge(&(bit_size - 8)));

        // check that the prime has the same number of bytes as requested
        assert!(prime.to_bytes_le().len().eq(&byte_size));

        let is_prime = Random::is_prime(&prime, 128);
        assert!(is_prime);
    }
}
