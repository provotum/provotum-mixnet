use crate::{Module, Trait};
use crypto::types::ModuloOperations;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sp_std::vec::Vec;

/// all functions related to zero-knowledge proofs in the offchain worker
impl<T: Trait> Module<T> {
    /// zips vectors a and b.
    /// performs component-wise operation: x = a_i^b_i % modulus
    /// multiplies all component-wise operation results
    /// Π(x) % modulus
    pub fn zip_vectors_multiply_a_pow_b(
        a: &Vec<BigUint>,
        b: &Vec<BigUint>,
        modulus: &BigUint,
    ) -> BigUint {
        assert!(a.len() == b.len(), "vectors must have the same length!");
        let iterator = a.iter().zip(b.iter());
        iterator.fold(BigUint::one(), |prod, (a_i, b_i)| {
            // Π(a_i^b_i % modulus) % modulus
            prod.modmul(&a_i.modpow(b_i, modulus), modulus)
        })
    }

    /// zips vectors a and b.
    /// performs component-wise operation: x = a_i * b_i % modulus
    /// sums all component-wise operation results
    /// Σ(x) % modulus
    pub fn zip_vectors_sum_products(
        a: &Vec<BigUint>,
        b: &Vec<BigUint>,
        modulus: &BigUint,
    ) -> BigUint {
        assert!(a.len() == b.len(), "vectors must have the same length!");
        let iterator = a.iter().zip(b.iter());
        // Σ(a_i * b_i) % modulus
        iterator.fold(BigUint::zero(), |sum, (a_i, b_i)| {
            sum.modadd(&a_i.modmul(b_i, modulus), modulus)
        })
    }
}
