use crate::types::{Cipher, ElGamalParams, PrivateKey, PublicKey};
use alloc::vec::Vec;
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

    /// Uses the Blak2 hash function and produces a hash of four different inputs. The result is returned as a BigUint.
    pub fn hash_inputs_to_biguint(id: usize, constant: &str, i: usize, x: BigUint) -> BigUint {
        let hasher = Blake2b::new();
        let hash = hasher
            .chain(id.to_be_bytes())
            .chain(constant.as_bytes())
            .chain(i.to_be_bytes())
            .chain(x.to_bytes_be())
            .finalize();
        BigUint::from_bytes_be(&hash)
    }

    /// GenShuffleProof Algorithm 8.3 (CHVoteSpec 3.1)
    ///
    /// Computes n independent generators of G_q ∈ Z*_p.
    /// The algorithm is an adaption of the NIST standard FIPS PUB 186-4 (Appendix A.2.3).
    /// Making the generators dependent on election id guarantees that the resulting values are specific to the current election.
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

    /// Uses the Blak2 hash function and produces a hash of a BigUint. The result is returned as a Vec<u8>.
    pub fn hash_biguint(input: &BigUint) -> Vec<u8> {
        let mut hasher = Blake2b::new();
        let data = input.to_bytes_be();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Uses the Blak2 hash function and produces a hash of a vector of BigUints. The result is returned as a Vec<u8>.
    pub fn hash_vec_biguints(inputs: Vec<BigUint>) -> Vec<u8> {
        let mut hash = Blake2b::new();

        for entry in inputs.iter() {
            hash = hash.chain(entry.to_bytes_be());
        }
        hash.finalize().to_vec()
    }

    /// Uses the Blak2 hash function and produces a hash of a vector of BigUints. The result is returned as a Vec<u8>.
    pub fn hash_vec_ciphers(inputs: Vec<Cipher>) -> Vec<u8> {
        let mut hash = Blake2b::new();

        for item in inputs.iter() {
            // transform both parts of Cipher (a,b) to a byte array
            // chain their hashes
            hash = hash.chain(item.a.to_bytes_be());
            hash = hash.chain(item.b.to_bytes_be());
        }

        hash.finalize().to_vec()
    }

    /// Uses the Blak2 hash function and produces a hash of a vector of BigUints. The result is returned as a BigUint.
    pub fn hash_vec_biguints_to_biguint(inputs: Vec<BigUint>) -> BigUint {
        let mut hash = Blake2b::new();

        for entry in inputs.iter() {
            hash = hash.chain(entry.to_bytes_be());
        }
        let digest = hash.finalize();
        BigUint::from_bytes_be(&digest)
    }

    /// Uses the Blak2 hash function and produces a hash of a vector of usize. The result is returned as a BigUint.
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
    pub fn hash_challenges_inputs(
        encryptions: Vec<Cipher>,
        shuffled_encryptions: Vec<Cipher>,
        commitments: Vec<BigUint>,
        pk: &PublicKey,
    ) -> BigUint {
        // hash all inputs into a single BigUint
        let mut hash = Blake2b::new();

        // hash public value
        let hash_encryptions = Helper::hash_vec_ciphers(encryptions);
        hash = hash.chain(hash_encryptions);

        let hash_shuffled_encryptions = Helper::hash_vec_ciphers(shuffled_encryptions);
        hash = hash.chain(hash_shuffled_encryptions);

        let hash_commitments = Helper::hash_vec_biguints(commitments);
        hash = hash.chain(hash_commitments);

        // transform the public key: h (BigUint) to byte array + hash it
        let hash_pk = Helper::hash_biguint(&pk.h);
        hash = hash.chain(hash_pk);

        // final byte array of all chained hashes + transform back to BigUint
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
        public_value: (
            Vec<Cipher>,
            Vec<Cipher>,
            Vec<BigUint>,
            Vec<BigUint>,
            &PublicKey,
        ),
        public_commitment: (BigUint, BigUint, BigUint, (BigUint, BigUint), Vec<BigUint>),
    ) -> BigUint {
        let (encryptions, shuffled_encryptions, permutation_commitments, chain_commitments, pk) =
            public_value;
        let (t1, t2, t3, (t4_1, t4_2), t_hat) = public_commitment;

        // hash all inputs into a single BigUint
        let mut hash = Blake2b::new();

        // hash public value
        let hash_encryptions = Helper::hash_vec_ciphers(encryptions);
        hash = hash.chain(hash_encryptions);

        let hash_shuffled_encryptions = Helper::hash_vec_ciphers(shuffled_encryptions);
        hash = hash.chain(hash_shuffled_encryptions);

        let hash_permutation_commitments = Helper::hash_vec_biguints(permutation_commitments);
        hash = hash.chain(hash_permutation_commitments);

        let hash_chain_commitments = Helper::hash_vec_biguints(chain_commitments);
        hash = hash.chain(hash_chain_commitments);

        // transform the public key: h (BigUint) to byte array + hash it
        let hash_pk = Helper::hash_biguint(&pk.h);
        hash = hash.chain(hash_pk);

        // hash public commitments
        let t_values = [t1, t2, t3, t4_1, t4_2];
        let hash_t_values = Helper::hash_vec_biguints(t_values.to_vec());
        hash = hash.chain(hash_t_values);

        let hash_t_hat_values = Helper::hash_vec_biguints(t_hat);
        hash = hash.chain(hash_t_hat_values);

        // final byte array of all chained hashes + transform back to BigUint
        let digest = hash.finalize();
        BigUint::from_bytes_be(&digest)
    }
}

#[cfg(test)]
mod tests {
    use super::Helper;
    use crate::types::{Cipher, ElGamalParams};
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
    fn it_should_hash_bigunit() {
        let expected_result = vec![
            149, 69, 186, 55, 178, 48, 216, 162, 231, 22, 196, 112, 117, 134, 84, 39, 128, 129, 91,
            124, 64, 136, 237, 203, 154, 246, 169, 69, 45, 80, 243, 36, 116, 213, 186, 154, 171,
            82, 166, 122, 202, 134, 78, 242, 105, 105, 129, 194, 234, 223, 73, 2, 4, 22, 19, 106,
            253, 131, 143, 176, 72, 210, 22, 83,
        ];
        let input = BigUint::one();
        let hash = Helper::hash_biguint(&input);
        assert_eq!(expected_result, hash);

        let input2 = BigUint::from(2u32);
        let hash2 = Helper::hash_biguint(&input2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn it_should_hash_vec_biguints() {
        let expected_result = vec![
            149, 69, 186, 55, 178, 48, 216, 162, 231, 22, 196, 112, 117, 134, 84, 39, 128, 129, 91,
            124, 64, 136, 237, 203, 154, 246, 169, 69, 45, 80, 243, 36, 116, 213, 186, 154, 171,
            82, 166, 122, 202, 134, 78, 242, 105, 105, 129, 194, 234, 223, 73, 2, 4, 22, 19, 106,
            253, 131, 143, 176, 72, 210, 22, 83,
        ];
        let input = [BigUint::one()];
        let hash = Helper::hash_vec_biguints(input.to_vec());
        assert_eq!(expected_result, hash);
    }

    #[test]
    fn it_should_hash_vec_ciphers() {
        let expected_result = vec![
            113, 148, 21, 201, 186, 138, 71, 207, 134, 55, 217, 216, 57, 88, 4, 19, 240, 140, 162,
            173, 176, 176, 248, 95, 170, 219, 110, 44, 253, 92, 250, 157, 124, 191, 67, 183, 127,
            166, 232, 113, 54, 224, 45, 35, 197, 177, 160, 28, 75, 81, 153, 115, 249, 46, 178, 219,
            192, 95, 124, 192, 190, 183, 165, 53,
        ];
        let input = [Cipher {
            a: BigUint::from(3u32),
            b: BigUint::from(7u32),
        }];
        let hash = Helper::hash_vec_ciphers(input.to_vec());
        assert_eq!(expected_result, hash);
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
    fn it_should_hash_vec_biguints_to_biguint() {
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
