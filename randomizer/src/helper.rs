use core::ops::Sub;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};

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
