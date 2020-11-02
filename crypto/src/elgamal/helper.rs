use crate::elgamal::types::{ElGamalParams, PrivateKey, PublicKey};
use alloc::vec::Vec;
use num_bigint::BigUint;
use num_traits::One;

pub struct Helper;

impl Helper {
    pub fn generate_key_pair(params: &ElGamalParams, r: &BigUint) -> (PublicKey, PrivateKey) {
        let sk = PrivateKey {
            params: params.clone(),
            x: r.clone(),
        };
        let h = params.g.modpow(&sk.x, &params.p);
        let pk = PublicKey {
            params: params.clone(),
            h,
        };
        (pk, sk)
    }

    // helper function to setup ElGamal system before a test
    pub fn setup_system(p: &[u8], g: &[u8], x: &[u8]) -> (ElGamalParams, PrivateKey, PublicKey) {
        let params = ElGamalParams {
            p: BigUint::parse_bytes(p, 10).unwrap(),
            g: BigUint::parse_bytes(g, 10).unwrap(),
        };
        let sk = PrivateKey {
            params: params.clone(),
            x: BigUint::parse_bytes(x, 10).unwrap(),
        };
        let pk = PublicKey {
            params: params.clone(),
            h: params.g.modpow(&sk.x, &params.p),
        };
        (params, sk, pk)
    }

    pub fn is_generator(params: &ElGamalParams) -> bool {
        let q = params.q();

        // g is a generator (valid) if:
        // 1. g != 1
        // 2. q != q
        // 3. g^q mod p == 1
        params.g != q
            && params.g != BigUint::one()
            && (params.g.modpow(&q, &params.p) == BigUint::one())
    }

    pub fn is_p_valid(_p: &BigUint) -> bool {
        // check if p is prime
        unimplemented!()
    }

    pub fn get_generator_candidates(_p: &BigUint) -> Vec<BigUint> {
        // 1. step: find q for the given p
        // 2. step: get all primitive roots for q
        // 3. step: check that g is a valid generator
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::Helper;
    use crate::elgamal::types::ElGamalParams;
    use num_bigint::BigUint;

    #[test]
    fn it_should_create_system() {
        let (params, sk, pk) = Helper::setup_system(b"23", b"2", b"4");

        // system parameters check: p, q, g
        assert_eq!(params.p, BigUint::from(23u32));
        assert_eq!(params.g, BigUint::from(2u32));
        assert_eq!(params.q(), BigUint::from(11u32));

        // private key check: x == x
        assert_eq!(sk.x, BigUint::from(4u32));

        // public key check: verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    fn it_should_create_a_key_pair() {
        let params = ElGamalParams {
            p: BigUint::from(7u32),
            // and, therefore, q -> 3
            g: BigUint::from(2u32),
        };

        // random value must be: r ∈ Zq = r ∈ {0,1,2}
        let r = BigUint::from(2u32);

        // create public/private key pair
        let (pk, sk) = Helper::generate_key_pair(&params, &r);

        assert_eq!(pk.params.p, BigUint::from(7u32));
        assert_eq!(pk.params.g, BigUint::from(2u32));
        assert_eq!(pk.params.q(), BigUint::from(3u32));

        assert_eq!(sk.params.p, BigUint::from(7u32));
        assert_eq!(sk.params.g, BigUint::from(2u32));
        assert_eq!(sk.x, BigUint::from(2u32));

        // verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    fn check_if_generator_success() {
        let test_params = ElGamalParams {
            p: BigUint::from(7u32),
            g: BigUint::from(2u32),
        };

        let g_is_a_generator = Helper::is_generator(&test_params);
        assert!(g_is_a_generator);
    }

    #[test]
    fn check_if_generator_failure() {
        let test_params = ElGamalParams {
            p: BigUint::from(7u32),
            g: BigUint::from(4u32),
        };

        let g_is_not_a_generator = Helper::is_generator(&test_params);
        assert!(g_is_not_a_generator);
    }
}
