use crate::{Error, Module, Trait};
use frame_support::debug;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::distributions::{Distribution, Uniform};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use sp_std::{vec, vec::Vec};

/// all functions related to random value generation in the offchain worker
impl<T: Trait> Module<T> {
    fn get_rng() -> ChaChaRng {
        // 32 byte array as random seed
        let seed: [u8; 32] = sp_io::offchain::random_seed();
        ChaChaRng::from_seed(seed)
    }

    // Miller-Rabin Primality Test
    // https://en.wikipedia.org/wiki/Miller-Rabin_primality_test
    pub fn is_prime(num: &BigUint, certainty: u32) -> Result<bool, Error<T>> {
        let zero: BigUint = BigUint::zero();
        let one: BigUint = BigUint::one();
        let two = one.clone() + one.clone();

        if *num == two {
            return Ok(true);
        }

        if num % two.clone() == zero {
            return Ok(false);
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

        // test for probable prime
        while k < certainty {
            let a = Self::get_random_bigunint_range(&two, num)?;
            let mut x = a.modpow(&d, num);
            if x != one.clone() && x != num_less_one {
                let mut random = zero.clone();
                loop {
                    x = x.modpow(&two, num);
                    if x == num_less_one {
                        break;
                    } else if x == one.clone() || random == (s.clone() - one.clone()) {
                        return Ok(false);
                    }
                    random += one.clone();
                }
            }
            k += 2;
        }
        Ok(true)
    }

    /// secure random number generation using OS randomness
    pub fn get_random_bytes(size: usize) -> Result<Vec<u8>, Error<T>> {
        // use chacha20 to produce random vector [u8] of size: size
        let mut rng = Self::get_rng();
        let mut bytes = vec![0; size];

        // try to fill the byte array with random values
        let random_value_generation = rng.try_fill_bytes(&mut bytes);

        match random_value_generation {
            // if successful, returns the random bytes.
            Ok(_) => Ok(bytes),
            // else, that the randomness generation failed.
            Err(error) => {
                debug::error!("randomness generation error: {:?}", error);
                Err(Error::RandomnessGenerationError)
            }
        }
    }

    // generate a random value: 0 < random < number
    pub fn get_random_biguint_less_than(upper: &BigUint) -> Result<BigUint, Error<T>> {
        if *upper <= BigUint::zero() {
            return Err(Error::RandomnessUpperBoundZeroError);
        }

        // determine the upper bound for the random value
        let upper_bound: BigUint = upper.clone() - BigUint::one();

        // the upper bound but in terms of bytes
        let size: usize = upper_bound.to_bytes_be().len();

        // fill an array of size: <size> with random bytes
        let random_bytes: Vec<u8> = Self::get_random_bytes(size)?;

        // try to transform the byte array into a biguint
        let mut random = BigUint::from_bytes_be(&random_bytes);

        // ensure: random < number
        random %= upper;

        Ok(random)
    }

    // generate a number of random biguints: all 0 < random < number
    pub fn get_random_biguints_less_than(
        upper: &BigUint,
        size: usize,
    ) -> Result<Vec<BigUint>, Error<T>> {
        let mut randoms: Vec<BigUint> = Vec::new();

        // try to fetch {size} random values < upper
        for _ in 0..size {
            let random: BigUint = Self::get_random_biguint_less_than(upper)?;
            randoms.push(random);
        }

        // if randoms is empty -> error occurred during get_random_biguint_less_than
        // since random cannot be pushed onto randoms, the list remains empty
        if randoms.is_empty() {
            Err(Error::RandomnessUpperBoundZeroError)
        } else {
            Ok(randoms)
        }
    }

    pub fn get_random_bigunint_range(
        lower: &BigUint,
        upper: &BigUint,
    ) -> Result<BigUint, Error<T>> {
        let mut rng = Self::get_rng();
        Self::random_bigunint_range(&mut rng, lower, upper)
    }

    fn random_bigunint_range(
        rng: &mut ChaChaRng,
        lower: &BigUint,
        upper: &BigUint,
    ) -> Result<BigUint, Error<T>> {
        if *upper == BigUint::zero() {
            return Err(Error::RandomRangeError);
        }
        if *lower >= *upper {
            return Err(Error::RandomRangeError);
        }
        let uniform = Uniform::new(lower, upper);
        let value: BigUint = uniform.sample(rng);
        Ok(value)
    }

    pub fn get_random_range(lower: usize, upper: usize) -> Result<usize, Error<T>> {
        let mut rng = Self::get_rng();
        Self::random_range(&mut rng, lower, upper)
    }

    fn random_range(rng: &mut ChaChaRng, lower: usize, upper: usize) -> Result<usize, Error<T>> {
        if upper == 0 {
            return Err(Error::RandomRangeError);
        }
        if lower >= upper {
            return Err(Error::RandomRangeError);
        }
        let uniform = Uniform::new(lower, upper);
        let value: usize = uniform.sample(rng);
        Ok(value)
    }

    pub fn generate_permutation(size: usize) -> Result<Vec<usize>, Error<T>> {
        if size == 0 {
            return Err(Error::PermutationSizeZeroError);
        }

        // vector containing the range of values from 0 up to the size of the vector - 1
        let mut permutation: Vec<usize> = Vec::new();
        let mut range: Vec<usize> = (0..size).collect();
        let mut rng = Self::get_rng();

        for index in 0..size {
            // get random integer
            let random: usize = Self::random_range(&mut rng, index, size)?;

            // get the element in the range at the random position
            let value = range.get(random).ok_or(Error::RandomRangeError)?;

            // store the value of the element at the random position
            permutation.push(*value);

            // swap positions
            range[random] = range[index];
        }
        Ok(permutation)
    }

    pub fn permute_vector(input: Vec<BigUint>, permutation: &[usize]) -> Vec<BigUint> {
        let mut temp_ = Vec::new();

        // permute the input vector
        // same order as permutation vector
        for i in 0..input.len() {
            let j_i = permutation[i];
            let u_j_i = input[j_i].clone();
            temp_.push(u_j_i);
        }

        // ensure that both arrays have the same length
        // i.e. nothing went wrong
        assert_eq!(input.len(), temp_.len());
        temp_
    }
}
