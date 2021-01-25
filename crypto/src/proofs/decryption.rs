use crate::{
    helper::Helper,
    types::{Cipher, ElGamalParams, ModuloOperations},
};
use alloc::vec::Vec;
use num_bigint::BigUint;
use std::println;

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub struct DecryptionProof {
    pub challenge: BigUint,
    pub response: BigUint,
}

impl DecryptionProof {
    /// GenShuffleProof Algorithm 8.50 (CHVoteSpec 3.2)
    ///
    /// Generates a decryption proof relative to encryptions e and partial decryptions c. This is essentially a NIZKP of knowledge of the private key sk satisfying c_i = b_i ^ sk for all input encryptions e_i = (a_i, b_i) and pk = g^sk.
    ///
    /// Step by Step:
    /// 1. generate a "second" key pair (a,b) = (random value from Z_q, g^a mod p)
    /// 2. compute challenge
    /// 3. compute d = a + c*sk
    pub fn generate(
        params: &ElGamalParams,
        sk: &BigUint,
        pk: &BigUint,
        r: &BigUint,
        vec_e: Vec<Cipher>,
        vec_c: Vec<BigUint>,
        id: &[u8],
    ) -> DecryptionProof {
        assert!(
            vec_e.len() == vec_c.len(),
            "encryptions and partial decryptions need to have the same length!"
        );
        assert!(!vec_e.is_empty(), "vectors cannot be empty!");

        // system parameters
        let g = &params.g;
        let q = &params.q();
        let p = &params.p;

        // number of items
        let n = vec_e.len();

        // the commitment
        let t_0 = g.modpow(r, p);
        println!("generate - t_0: {:?}", t_0);

        // get commitments for all encryptions
        let mut vec_t: Vec<BigUint> = Vec::with_capacity(n + 1);
        vec_t.push(t_0);

        for e_i in vec_e.iter() {
            let t_i = e_i.a.modpow(r, p);
            println!("generate - e_i.a: {:?}, t_i: {:?}", e_i.a, t_i);
            vec_t.push(t_i);
        }

        // compute challenge
        // hash public values (hash(unique_id, constant, pk, e, c, vec_t) mod q)
        let mut c = Helper::hash_decryption_proof_inputs(id, "decryption", pk, vec_e, vec_c, vec_t);

        println!("c: {:?}, q: {:?}", c, q);

        c %= q;

        // compute the response: d = r - c * sk mod q
        let c_sk = c.modmul(sk, q);
        let d = r.modsub(&c_sk, q);
        println!("generate - r: {:?}, c: {:?}, d: {:?}", r, c, d);
        println!("");

        DecryptionProof {
            challenge: c,
            response: d,
        }
    }

    /// CheckDecryptionProof Algorithm 8.51 (CHVoteSpec 3.2)
    ///
    /// Verifies a proof of knowledge of a secret key (sk) that belongs to a public key (pk = g^sk) using the Schnorr protocol. It is a proof of knowledge of a discrete logarithm of x = log_g(g^x).
    ///
    /// Step by Step:
    /// 1. recompute b = g^d/h^c
    /// 2. recompute the challenge c
    /// 3. verify that the challenge is correct
    /// 4. verify that: g^d == b * h^c
    pub fn verify(
        params: &ElGamalParams,
        pk: &BigUint,
        proof: &DecryptionProof,
        vec_e: Vec<Cipher>,
        vec_c: Vec<BigUint>,
        id: &[u8],
    ) -> bool {
        assert!(
            vec_e.len() == vec_c.len(),
            "encryptions and partial decryptions need to have the same length!"
        );
        assert!(!vec_e.is_empty(), "vectors cannot be empty!");

        // system parameters
        let g = &params.g;
        let q = &params.q();
        let p = &params.p;

        // number of items
        let n = vec_e.len();

        // the proof
        let c = &proof.challenge;
        let d = &proof.response;

        // the recomputed commitment
        // t_0 = pk^c * g^d mod p
        let pk_c = pk.modpow(&c, p);
        let g_d = g.modpow(d, p);
        let t_0 = pk_c.modmul(&g_d, p);
        println!("verify - t_0: {:?}", t_0);

        // recompute all commitments for all encryptions
        let mut recompute_vec_t: Vec<BigUint> = Vec::with_capacity(n + 1);
        recompute_vec_t.push(t_0);

        for index in 0..n {
            let a_i = &vec_e[index].a;
            let c_i = &vec_c[index];

            // recompute t_i = c_i^c * a_i^d mod p
            let c_i_c = c_i.modpow(&c, p);
            let a_i_d = a_i.modpow(&d, p);
            let t_i = c_i_c.modmul(&a_i_d, p);
            println!(
                "verify - e_i.a: {:?}, c_i: {:?}, c: {:?}, c_i_c: {:?}, a_i_d: {:?}, t_{:?}: {:?}",
                a_i,
                c_i,
                c,
                c_i_c,
                a_i_d,
                index + 1,
                t_i
            );
            recompute_vec_t.push(t_i);
        }

        // recompute the challenge
        // hash public values (hash(unique_id, constant, pk, vec_e, vec_c, recompute_vec_t) mod q)
        let mut recomputed_c = Helper::hash_decryption_proof_inputs(
            id,
            "decryption",
            pk,
            vec_e,
            vec_c,
            recompute_vec_t,
        );
        recomputed_c %= q;
        println!("verify - c: {:?}", recomputed_c);

        // verify that the challenges are the same
        &recomputed_c == c
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encryption::ElGamal, helper::Helper, proofs::decryption::DecryptionProof, random::Random,
    };
    use alloc::vec::Vec;
    use num_bigint::BigUint;

    #[test]
    fn it_should_create_decryption_proof_tiny() {
        let sealer_id = "Bob".as_bytes();
        let (params, sk, pk) = Helper::setup_tiny_system();
        let q = &params.q();
        let r = BigUint::parse_bytes(b"B", 16).unwrap();

        // get three encrypted values: 0, 1, 2
        let encryptions = Random::generate_random_encryptions(&pk, q).to_vec();
        let decryptions = encryptions
            .iter()
            .map(|cipher| ElGamal::decrypt(cipher, &sk))
            .collect::<Vec<BigUint>>();

        let proof = DecryptionProof::generate(
            &params,
            &sk.x,
            &pk.h,
            &r,
            encryptions,
            decryptions,
            sealer_id,
        );
        assert!(proof);
    }

    #[test]
    fn it_should_verify_decryption_proof() {
        let sealer_id = "Charlie".as_bytes();
        let (params, sk, pk) = Helper::setup_tiny_system();
        let q = &params.q();
        println!("setup - q: {}", q);
        // let r = Random::get_random_less_than(q);
        let r = BigUint::from(8u32);

        // get three encrypted values: 0, 1, 2
        let encryptions = Random::generate_random_encryptions(&pk, q).to_vec();
        let decryptions = encryptions
            .iter()
            .map(|cipher| ElGamal::decrypt(cipher, &sk))
            .collect::<Vec<BigUint>>();

        let proof = DecryptionProof::generate(
            &params,
            &sk.x,
            &pk.h,
            &r,
            encryptions.clone(),
            decryptions.clone(),
            sealer_id,
        );

        // verify the proof
        let is_correct =
            DecryptionProof::verify(&params, &pk.h, &proof, encryptions, decryptions, sealer_id);
        assert!(is_correct);
    }
}
