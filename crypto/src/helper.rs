use crate::types::{Cipher, ElGamalParams, PrivateKey, PublicKey};
use alloc::{format, vec::Vec};
use blake2::{Blake2b, Digest};
use num_bigint::BigUint;
use num_traits::{One, Zero};

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
    pub fn setup_system(p: &[u8], x: &[u8]) -> (ElGamalParams, PrivateKey, PublicKey) {
        let params = ElGamalParams {
            p: BigUint::parse_bytes(p, 10).unwrap(),
            g: BigUint::parse_bytes(b"4", 10).unwrap(),
            h: BigUint::parse_bytes(b"9", 10).unwrap(),
        };
        assert!(
            Self::is_generator(&params.p, &params.q(), &params.g),
            "g is not a generator!"
        );
        assert!(
            Self::is_generator(&params.p, &params.q(), &params.h),
            "h is not a generator!"
        );
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

    pub fn is_generator(p: &BigUint, q: &BigUint, g: &BigUint) -> bool {
        // g is a generator (valid) if:
        // 1. g != 1
        // 2. q != q
        // 3. g^q mod p == 1
        let one = BigUint::one();
        g != q && g != &one && (g.modpow(q, p) == one)
    }

    pub fn is_p_valid(_p: &BigUint) -> bool {
        // check if p is prime
        unimplemented!()
    }

    /// Uses the Blak2 hash function and produces a hash of four different inputs.
    ///
    /// The result is returned as a BigUint.
    pub fn hash_inputs_to_biguint(id: usize, constant: &str, i: usize, x: BigUint) -> BigUint {
        let hasher = Blake2b::new();
        let hash = hasher
            .chain(id.to_be_bytes())
            .chain(constant)
            .chain(i.to_be_bytes())
            .chain(x.to_bytes_be())
            .finalize();
        BigUint::from_bytes_be(&hash)
    }

    /// Returns {number} independent generators of G_q ∈ Z*_p.
    ///
    /// The algorithm is an adaption of the NIST standard FIPS PUB 186-4 (Appendix A.2.3)
    pub fn get_generators(id: usize, q: &BigUint, number: usize) -> Vec<BigUint> {
        let mut generators: Vec<BigUint> = Vec::new();
        for i in 0..number {
            let zero = BigUint::zero();
            let one = BigUint::one();
            let two = BigUint::from(2u32);

            // start
            let mut x = zero.clone();

            let mut h_i = zero.clone();
            while h_i == zero || h_i == one {
                x += one.clone();

                // hash all inputs and transform to a biguint
                h_i = Self::hash_inputs_to_biguint(id, "ggen", i, x.clone());
                h_i %= q;
                h_i = h_i.modpow(&two, q);
            }
            generators.push(h_i);
        }
        generators
    }

    /// Uses the Blak2 hash function and produces a hash of a vector of BigUints.
    ///
    /// The result is returned as a BigUint.
    pub fn hash_vec_biguints_to_biguint(inputs: Vec<BigUint>) -> BigUint {
        let mut hash = Blake2b::new();

        for entry in inputs.iter() {
            hash = hash.chain(entry.to_bytes_be());
        }
        let digest = hash.finalize();
        BigUint::from_bytes_be(&digest)
    }

    /// Uses the Blak2 hash function and produces a hash of a vector of usize.
    ///
    /// The result is returned as a BigUint.
    pub fn hash_vec_usize_to_biguint(inputs: &[usize]) -> BigUint {
        let mut hash = Blake2b::new();

        for entry in inputs.iter() {
            hash = hash.chain(entry.to_be_bytes());
        }
        let digest = hash.finalize();
        BigUint::from_bytes_be(&digest)
    }

    /// Computes the hash of all inputs.
    ///
    /// Inputs:
    /// - encryptions: Vec<Cipher>
    /// - shuffled_encryptions: Vec<Cipher>
    /// - commitments: Vec<BigUint>
    /// - pk: PublicKey
    pub fn hash_challenge_inputs(
        encryptions: Vec<Cipher>,
        shuffled_encryptions: Vec<Cipher>,
        commitments: Vec<BigUint>,
        pk: &PublicKey,
    ) -> BigUint {
        // hash all inputs into a single BigUint
        let mut hash = Blake2b::new();

        for item in encryptions.iter() {
            // transform both parts of Cipher (a,b) to a byte array + chain their hashes
            hash = hash.chain(item.a.to_bytes_be()).chain(item.b.to_bytes_be());
        }

        for item in shuffled_encryptions.iter() {
            // transform both parts of Cipher (a,b) to a byte array + chain their hashes
            hash = hash.chain(item.a.to_bytes_be()).chain(item.b.to_bytes_be());
        }

        for item in commitments.iter() {
            // transform BigUint to byte array + chain the hash
            hash = hash.chain(item.to_bytes_be());
        }

        // transform the public key: h (BigUint) to byte array + chain the hash
        hash = hash.chain(pk.h.to_bytes_be());

        // final byte array of all chained hashes + transform back to BigUint
        let digest = hash.finalize();
        BigUint::from_bytes_be(&digest)
    }
}

#[cfg(test)]
mod tests {
    use super::Helper;
    use crate::types::ElGamalParams;
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    fn it_should_create_system() {
        let (params, sk, pk) = Helper::setup_system(b"23", b"4");

        // system parameters check: p, q, g
        assert_eq!(params.p, BigUint::from(23u32));
        assert_eq!(params.g, BigUint::from(4u32));
        assert_eq!(params.h, BigUint::from(9u32));
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
            h: BigUint::from(3u32),
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
    fn check_if_5_is_a_generator_of_p7_failure() {
        let params = ElGamalParams {
            p: BigUint::from(7u32),
            // q = 3
            g: BigUint::from(2u32),
            h: BigUint::from(3u32),
        };

        let g_is_not_a_generator =
            Helper::is_generator(&params.p, &params.q(), &BigUint::from(5u32));
        assert!(!g_is_not_a_generator);
    }

    #[test]
    fn check_if_g_and_h_are_generators_success() {
        let params = ElGamalParams {
            p: BigUint::from(23u32),
            // q = 11
            g: BigUint::from(4u32),
            h: BigUint::from(9u32),
        };

        let g_is_a_generator = Helper::is_generator(&params.p, &params.q(), &params.g);
        assert!(g_is_a_generator);

        let h_is_a_generator = Helper::is_generator(&params.p, &params.q(), &params.h);
        assert!(h_is_a_generator);
    }

    #[test]
    fn it_should_hash_and_return_biguint() {
        let id: usize = 1;
        let constant = "ggen";
        let mut i: usize = 1;
        let x = BigUint::one();
        let hash1 = Helper::hash_inputs_to_biguint(id, constant, i, x.clone());

        i = 2;
        let hash2 = Helper::hash_inputs_to_biguint(id, constant, i, x);

        let one = BigUint::one();
        assert!(hash1 > one.clone());
        assert!(hash2 > one);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn it_should_get_generators() {
        let one = BigUint::one();
        let id: usize = 1;
        let (params, _, _) = Helper::setup_system(
            b"170141183460469231731687303715884105727",
            b"1701411834604692317316",
        );

        let generators = Helper::get_generators(id, &params.q(), 10);
        assert_eq!(generators.len(), 10);
        assert!(generators.iter().all(|value| value.clone() > one));
    }

    #[test]
    fn it_should_hash_biguints() {
        let one = BigUint::one();
        let hash1 = Helper::hash_vec_biguints_to_biguint([one.clone()].to_vec());

        let two = BigUint::from(2u32);
        let hash2 = Helper::hash_vec_biguints_to_biguint([two.clone()].to_vec());
        assert_ne!(hash1, hash2);

        let combined = Helper::hash_vec_biguints_to_biguint([one, two].to_vec());
        assert_ne!(combined, hash1);
        assert_ne!(combined, hash2);
    }
}
