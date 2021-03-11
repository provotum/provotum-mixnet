use crate::types::{BigT, BigY, Cipher, ElGamalParams, PrivateKey, PublicKey};
use alloc::vec::Vec;
use blake2::{Blake2b, Digest};
use num_bigint::BigUint;
use num_traits::{One, Zero};

pub struct Helper;

impl Helper {
    pub fn generate_key_pair(params: &ElGamalParams, r: &BigUint) -> (PublicKey, PrivateKey) {
        assert!(
            Self::is_generator(&params.p, &params.q(), &params.h),
            "h is not a generator!"
        );
        assert!(
            Self::is_generator(&params.p, &params.q(), &params.g),
            "g is not a generator!"
        );
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

    pub fn setup_xl_system() -> (ElGamalParams, PrivateKey, PublicKey) {
        // 3072bit key
        let p = BigUint::parse_bytes(b"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7", 16).unwrap();
        let x = BigUint::parse_bytes(b"ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7", 16).unwrap();
        Self::setup_system(p, x)
    }

    pub fn setup_lg_system() -> (ElGamalParams, PrivateKey, PublicKey) {
        // 2048bit key
        let p = BigUint::parse_bytes(b"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063", 16).unwrap();
        let x = BigUint::parse_bytes(b"E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC6DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063", 16).unwrap();
        Self::setup_system(p, x)
    }

    pub fn setup_md_system() -> (ElGamalParams, PrivateKey, PublicKey) {
        // 1024bit key
        let p = BigUint::parse_bytes(b"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC942593", 16).unwrap();
        let x = BigUint::parse_bytes(b"5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35", 16).unwrap();
        Self::setup_system(p, x)
    }

    pub fn setup_512bit_system() -> (ElGamalParams, PrivateKey, PublicKey) {
        // 512bit key
        let p = BigUint::parse_bytes(b"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5F9E3", 16).unwrap();
        let x = BigUint::parse_bytes(b"38B4DA56A784D9045190CFEF324E77389", 16).unwrap();
        Self::setup_system(p, x)
    }

    pub fn setup_256bit_system() -> (ElGamalParams, PrivateKey, PublicKey) {
        // 256bit key
        let p = BigUint::parse_bytes(
            b"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D904519216D3",
            16,
        )
        .unwrap();
        let x = BigUint::parse_bytes(b"7158809CF4F3C762E7160F38B4DA56", 16).unwrap();
        Self::setup_system(p, x)
    }

    pub fn setup_sm_system() -> (ElGamalParams, PrivateKey, PublicKey) {
        // 48bit key
        let p = BigUint::parse_bytes(b"B7E151629927", 16).unwrap();
        let x = BigUint::parse_bytes(b"5BF0A8B1", 16).unwrap();
        Self::setup_system(p, x)
    }

    pub fn setup_tiny_system() -> (ElGamalParams, PrivateKey, PublicKey) {
        // 6bit key
        let p = BigUint::parse_bytes(b"47", 10).unwrap();
        let x = BigUint::parse_bytes(b"17", 10).unwrap();
        Self::setup_system(p, x)
    }

    // helper function to setup ElGamal system before a test
    fn setup_system(p: BigUint, x: BigUint) -> (ElGamalParams, PrivateKey, PublicKey) {
        let params = ElGamalParams {
            p,
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
            x,
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
    pub fn hash_inputs_to_biguint(id: &[u8], constant: &str, i: usize, x: BigUint) -> BigUint {
        let hasher = Blake2b::new();
        let hash = hasher
            .chain(id)
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
    pub fn get_generators(id: &[u8], p: &BigUint, number: usize) -> Vec<BigUint> {
        let mut vec_h: Vec<BigUint> = Vec::new();
        let zero = BigUint::zero();
        let one = BigUint::one();
        let two = BigUint::from(2u32);

        for i in 0..number {
            // start
            let mut x = zero.clone();
            let mut h_i = zero.clone();

            while h_i == zero || h_i == one {
                x += one.clone();

                // hash all inputs and transform to a biguint
                h_i = Self::hash_inputs_to_biguint(id, "ggen", i, x.clone());
                h_i %= p;
                h_i = h_i.modpow(&two, p);
            }
            vec_h.push(h_i);
        }
        vec_h
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

    pub fn hash_key_gen_proof_inputs(
        id: &[u8],
        constant: &str,
        h: &BigUint,
        b: &BigUint,
    ) -> BigUint {
        let hasher = Blake2b::new();
        let hash = hasher
            .chain(id)
            .chain(constant.as_bytes())
            .chain(h.to_bytes_be())
            .chain(b.to_bytes_be())
            .finalize();
        BigUint::from_bytes_be(&hash)
    }

    pub fn hash_decryption_proof_inputs(
        id: &[u8],
        constant: &str,
        h: &BigUint,
        vec_e: Vec<Cipher>,
        vec_c: Vec<BigUint>,
        vec_t: Vec<BigUint>,
    ) -> BigUint {
        let hasher = Blake2b::new();
        let mut hash = hasher
            .chain(id)
            .chain(constant.as_bytes())
            .chain(h.to_bytes_be());

        let hash_e = Helper::hash_vec_ciphers(vec_e);
        hash = hash.chain(hash_e);

        let hash_c = Helper::hash_vec_biguints(vec_c);
        hash = hash.chain(hash_c);

        let hash_vec_t = Helper::hash_vec_biguints(vec_t);
        hash = hash.chain(hash_vec_t);

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
    /// - public_value: Y
    /// - public_commitment: T
    pub fn hash_challenge_inputs(public_value: BigY, public_commitment: BigT) -> BigUint {
        let (e, e_tilde, vec_c, vec_c_hat, public_key) = public_value;
        let (t1, t2, t3, t4_1, t4_2, vec_t_hat) = public_commitment;

        // hash all inputs into a single BigUint
        let mut hash = Blake2b::new();

        // hash public value
        let hash_e = Helper::hash_vec_ciphers(e);
        hash = hash.chain(hash_e);

        let hash_e_tilde = Helper::hash_vec_ciphers(e_tilde);
        hash = hash.chain(hash_e_tilde);

        let hash_vec_c = Helper::hash_vec_biguints(vec_c);
        hash = hash.chain(hash_vec_c);

        let hash_vec_c_hat = Helper::hash_vec_biguints(vec_c_hat);
        hash = hash.chain(hash_vec_c_hat);

        let hash_pk = Helper::hash_biguint(public_key);
        hash = hash.chain(hash_pk);

        // hash public commitments
        let t_values = [t1, t2, t3, t4_1, t4_2];
        let hash_t_values = Helper::hash_vec_biguints(t_values.to_vec());
        hash = hash.chain(hash_t_values);

        let hash_vec_t_hat = Helper::hash_vec_biguints(vec_t_hat);
        hash = hash.chain(hash_vec_t_hat);

        // final byte array of all chained hashes + transform back to BigUint
        let digest = hash.finalize();
        BigUint::from_bytes_be(&digest)
    }
}

#[cfg(test)]
mod tests {
    use super::Helper;
    use crate::{
        random::Random,
        types::{Cipher, ElGamalParams},
    };
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    fn it_should_create_sm_system() {
        let (params, sk, pk) = Helper::setup_sm_system();

        // system parameters check: p, q, g
        assert!(Random::is_prime(&params.p, 20));
        assert_eq!(params.p, BigUint::parse_bytes(b"B7E151629927", 16).unwrap());
        assert_eq!(params.g, BigUint::from(4u32));
        assert_eq!(params.h, BigUint::from(9u32));
        assert!(Random::is_prime(&params.q(), 20));
        assert_eq!(params.q(), BigUint::from(101089180470419u64));

        // private key check: x == x
        assert_eq!(sk.x, BigUint::parse_bytes(b"5BF0A8B1", 16).unwrap());

        // public key check: verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    fn it_should_create_tiny_system() {
        let (params, sk, pk) = Helper::setup_tiny_system();

        // check that p & are prime
        assert!(Random::is_prime(&params.p, 20));
        assert!(Random::is_prime(&params.q(), 20));

        // public key check: verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    fn it_should_create_256bit_system() {
        let (params, sk, pk) = Helper::setup_256bit_system();

        // check that p & are prime
        assert!(Random::is_prime(&params.p, 20));
        assert!(Random::is_prime(&params.q(), 20));

        // public key check: verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    fn it_should_create_512bit_system() {
        let (params, sk, pk) = Helper::setup_512bit_system();

        // check that p & are prime
        assert!(Random::is_prime(&params.p, 20));
        assert!(Random::is_prime(&params.q(), 20));

        // public key check: verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    fn it_should_create_md_system() {
        let (params, sk, pk) = Helper::setup_md_system();

        // check that p & are prime
        assert!(Random::is_prime(&params.p, 20));
        assert!(Random::is_prime(&params.q(), 20));

        // public key check: verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    #[ignore = "takes more than 10s to complete, only run when necessary"]
    fn it_should_create_lg_system() {
        let (params, sk, pk) = Helper::setup_lg_system();

        // check that p & are prime
        assert!(Random::is_prime(&params.p, 20));
        assert!(Random::is_prime(&params.q(), 20));

        // public key check: verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    #[ignore = "takes more than 10s to complete, only run when necessary"]
    fn it_should_create_xl_system() {
        let (params, sk, pk) = Helper::setup_xl_system();

        // check that p & are prime
        assert!(Random::is_prime(&params.p, 20));
        assert!(Random::is_prime(&params.q(), 20));

        // public key check: verify that h == g^x mod p
        assert_eq!(pk.h, sk.params.g.modpow(&sk.x, &sk.params.p));
    }

    #[test]
    fn it_should_create_a_key_pair() {
        let params = ElGamalParams {
            p: BigUint::from(23u32),
            // and, therefore, q -> 11
            g: BigUint::from(4u32),
            h: BigUint::from(9u32),
        };

        // random value must be: r ∈ Zq = r ∈ {0,1,2,3,4,5,6,7,8,9,10}
        let r = BigUint::from(2u32);

        // create public/private key pair
        let (pk, sk) = Helper::generate_key_pair(&params, &r);

        assert_eq!(pk.params.p, BigUint::from(23u32));
        assert_eq!(pk.params.g, BigUint::from(4u32));
        assert_eq!(pk.params.h, BigUint::from(9u32));
        assert_eq!(pk.params.q(), BigUint::from(11u32));

        assert_eq!(sk.params.p, BigUint::from(23u32));
        assert_eq!(sk.params.g, BigUint::from(4u32));
        assert_eq!(sk.params.h, BigUint::from(9u32));
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
        let id = "2020-12-12_01".as_bytes();
        let constant = "ggen";
        let mut i: usize = 1;
        let x = BigUint::one();
        let hash1 = Helper::hash_inputs_to_biguint(&id, constant, i, x.clone());

        i = 2;
        let hash2 = Helper::hash_inputs_to_biguint(&id, constant, i, x);

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
        let id = "2020-12-12_01".as_bytes();
        let num: usize = 10;
        let (params, _, _) = Helper::setup_md_system();

        let generators = Helper::get_generators(&id, &params.p, num);
        assert_eq!(generators.len(), num);
        assert!(generators.iter().all(|gen| gen.clone() > one));
        assert!(generators
            .iter()
            .all(|gen| Helper::is_generator(&params.p, &params.q(), gen)));
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
