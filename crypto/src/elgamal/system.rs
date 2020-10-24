use alloc::vec::Vec;
use core::ops::{Div, Sub};
use num_bigint::BigUint;
use num_traits::One;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ElGamalParams {
    // modulus: p
    pub p: BigUint,

    // generator: g
    pub g: BigUint,
}

impl ElGamalParams {
    // q:
    // q is valid if it is prime
    pub fn q(&self) -> BigUint {
        (self.p.clone().sub(1 as u32)).div(2 as u32)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PublicKey {
    // system parameters (p, g)
    pub params: ElGamalParams,

    // public key: h
    pub h: BigUint,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PrivateKey {
    // system parameters (p, g)
    pub params: ElGamalParams,

    // private key: x
    pub x: BigUint,
}

pub mod helpers {
    use super::*;

    pub fn is_generator(params: &ElGamalParams) -> bool {
        let p = params.p.clone();
        let g = params.g.clone();
        let q = params.q();

        // g is a generator (valid) if:
        // 1. g != 1
        // 2. q != q
        // 3. g^q mod p == 1
        g != q && g != BigUint::one() && (g.modpow(&q, &p) == BigUint::one())
    }

    pub fn get_generator_candidates(p: &BigUint) -> Vec<BigUint> {
        // 1. step: find q for the given p
        // 2. step: get all primitive roots for q
        // 3. step: check that g is a valid generator
        unimplemented!()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn check_if_q_is_correctly_computed() {
            let test_params = ElGamalParams {
                p: BigUint::from(7 as u32),
                g: BigUint::from(2 as u32),
            };

            let expected_q = BigUint::from(3 as u32);
            let q = test_params.q();
            assert_eq!(expected_q, q);
        }

        #[test]
        fn check_if_generator_success() {
            let test_params = ElGamalParams {
                p: BigUint::from(7 as u32),
                g: BigUint::from(2 as u32),
            };

            let g_is_a_generator = is_generator(&test_params);
            assert!(g_is_a_generator);
        }

        #[test]
        fn check_if_generator_failure() {
            let test_params = ElGamalParams {
                p: BigUint::from(7 as u32),
                g: BigUint::from(4 as u32),
            };

            let g_is_not_a_generator = is_generator(&test_params);
            assert!(g_is_not_a_generator);
        }
    }
}
