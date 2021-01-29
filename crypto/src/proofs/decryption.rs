use crate::{
    helper::Helper,
    types::{Cipher, ElGamalParams, ModuloOperations},
};
use alloc::vec::Vec;
use num_bigint::BigUint;

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
    /// 3. compute d = a + c * sk
    pub fn generate(
        params: &ElGamalParams,
        sk: &BigUint, // private key of public key share
        pk: &BigUint, // public key of public key share -> not system public key
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

        // the commitment
        let t_0 = g.modpow(r, p);

        // get commitments for all encryptions
        let mut vec_t: Vec<BigUint> = Vec::with_capacity(vec_e.len() + 1);
        vec_t.push(t_0);

        for e_i in vec_e.iter() {
            let t_i = e_i.a.modpow(r, p);
            vec_t.push(t_i);
        }

        // compute challenge
        // hash public values (hash(unique_id, constant, pk, e, c, vec_t) mod q)
        let mut c = Helper::hash_decryption_proof_inputs(id, "decryption", pk, vec_e, vec_c, vec_t);
        c %= q;

        // compute the response: d = r - c * sk mod q
        let d = r.modsub(&c.modmul(sk, q), q);

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
        pk: &BigUint, // public key of public key share -> not system public key
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

        // the proof
        let c = &proof.challenge;
        let d = &proof.response;

        // the recomputed commitment
        // t_0 = pk^c * g^d mod p
        let pk_c = pk.modpow(&c, p);
        let g_d = g.modpow(d, p);
        let t_0 = pk_c.modmul(&g_d, p);

        // recompute all commitments for all encryptions
        let mut recompute_vec_t: Vec<BigUint> = Vec::with_capacity(vec_e.len() + 1);
        recompute_vec_t.push(t_0);

        for index in 0..vec_e.len() {
            let a_i = &vec_e[index].a;
            let c_i = &vec_c[index];

            // recompute t_i = c_i^c * a_i^d mod p
            let c_i_c = c_i.modpow(&c, p);
            let a_i_d = a_i.modpow(&d, p);
            let t_i = c_i_c.modmul(&a_i_d, p);
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

        // verify that the challenges are the same
        &recomputed_c == c
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encryption::ElGamal,
        helper::Helper,
        proofs::decryption::DecryptionProof,
        random::Random,
        types::{ElGamalParams, ModuloOperations, PublicKey},
    };
    use alloc::vec::Vec;
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use std::time::Instant;

    #[test]
    fn it_should_verify_decryption_proof() {
        let sealer_id = "Charlie".as_bytes();
        let (params, sk, pk) = Helper::setup_sm_system();
        let q = &params.q();
        let r = Random::get_random_less_than(q);

        // get three encrypted values: 1, 3, 5
        let encryptions = Random::generate_random_encryptions(&pk, q, 3);

        // get partial decryptions -> only decrypt component a: g^r -> g^r^sk
        let decryptions = encryptions
            .iter()
            .map(|cipher| ElGamal::partial_decrypt_a(cipher, &sk))
            .collect::<Vec<BigUint>>();

        // create a proof for the partial decryptions
        let proof = DecryptionProof::generate(
            &params,
            &sk.x,
            &pk.h,
            &r,
            encryptions.clone(),
            decryptions.clone(),
            sealer_id,
        );

        // verify that the proof is correct
        let is_correct =
            DecryptionProof::verify(&params, &pk.h, &proof, encryptions, decryptions, sealer_id);
        assert!(is_correct);
    }

    #[test]
    fn it_should_verify_decryption_proof_multiple_partial_decryptions() {
        // create system parameters
        let params = ElGamalParams {
            // 48bit key -> sm_system
            p: BigUint::parse_bytes(b"B7E151629927", 16).unwrap(),
            g: BigUint::parse_bytes(b"4", 10).unwrap(),
            h: BigUint::parse_bytes(b"9", 10).unwrap(),
        };
        let q = &params.q();

        // create bob's public and private key
        let bob_id = "Bob".as_bytes();
        let bob_sk_x = Random::get_random_less_than(q);
        let (bob_pk, bob_sk) = Helper::generate_key_pair(&params, &bob_sk_x);

        // create charlie's public and private key
        let charlie_id = "Charlie".as_bytes();
        let charlie_sk_x = Random::get_random_less_than(q);
        let (charlie_pk, charlie_sk) = Helper::generate_key_pair(&params, &charlie_sk_x);

        // create common public key
        let combined_pk = PublicKey {
            h: bob_pk.h.modmul(&charlie_pk.h, &bob_pk.params.p),
            params: params.clone(),
        };

        let start = Instant::now();
        println!("start generation random encryptions");

        // get three encrypted values: 1, 3, 5 using the generated common public key
        let encryptions = Random::generate_random_encryptions(&combined_pk, q, 3);

        let duration = start.elapsed();
        println!("duration generate_random_encryptions: {:?}", duration);

        // get bob's partial decryptions
        let bob_partial_decrytpions = encryptions
            .iter()
            .map(|cipher| ElGamal::partial_decrypt_a(cipher, &bob_sk))
            .collect::<Vec<BigUint>>();

        let duration = start.elapsed();
        println!("duration bob_partial_decrytpions: {:?}", duration);

        // create bob's proof
        let r = Random::get_random_less_than(q);
        let bob_proof = DecryptionProof::generate(
            &params,
            &bob_sk.x,
            &bob_pk.h,
            &r,
            encryptions.clone(),
            bob_partial_decrytpions.clone(),
            bob_id,
        );

        let duration = start.elapsed();
        println!("duration DecryptionProof::generate: {:?}", duration);

        // verify that bob's proof is correct
        let bob_proof_is_correct = DecryptionProof::verify(
            &params,
            &bob_pk.h,
            &bob_proof,
            encryptions.clone(),
            bob_partial_decrytpions.clone(),
            bob_id,
        );
        assert!(bob_proof_is_correct);
        let duration = start.elapsed();
        println!("duration DecryptionProof::verify: {:?}", duration);

        // get charlie's partial decryptions
        let charlie_partial_decrytpions = encryptions
            .iter()
            .map(|cipher| ElGamal::partial_decrypt_a(cipher, &charlie_sk))
            .collect::<Vec<BigUint>>();

        let duration = start.elapsed();
        println!("duration charlie_partial_decrytpions: {:?}", duration);

        // create charlie's proof
        let r = Random::get_random_less_than(q);
        let charlie_proof = DecryptionProof::generate(
            &params,
            &charlie_sk.x,
            &charlie_pk.h,
            &r,
            encryptions.clone(),
            charlie_partial_decrytpions.clone(),
            charlie_id,
        );

        let duration = start.elapsed();
        println!("duration DecryptionProof::generate: {:?}", duration);

        // verify that charlie's proof is correct
        let charlie_proof_is_correct = DecryptionProof::verify(
            &params,
            &charlie_pk.h,
            &charlie_proof,
            encryptions.clone(),
            charlie_partial_decrytpions.clone(),
            charlie_id,
        );
        assert!(charlie_proof_is_correct);

        let duration = start.elapsed();
        println!("duration DecryptionProof::verify: {:?}", duration);

        // combine partial decrypted components a
        let combined_decryptions = ElGamal::combine_partial_decrypted_as(
            vec![bob_partial_decrytpions, charlie_partial_decrytpions],
            &params.p,
        );
        let duration = start.elapsed();
        println!("duration combine_partial_decrypted_as: {:?}", duration);

        // retrieve the plaintext votes
        // by combining the decrypted components a with their decrypted components b
        let iterator = encryptions.iter().zip(combined_decryptions.iter());
        let plaintexts = iterator
            .map(|(cipher, decrypted_a)| {
                ElGamal::partial_decrypt_b(&cipher.b, decrypted_a, &params.p)
            })
            .collect::<Vec<BigUint>>();
        let duration = start.elapsed();
        println!("duration partial_decrypt_b: {:?}", duration);

        // check that at least one value is 1, 2, 4
        assert!(plaintexts.len() == 3, "there should be three plaintexts");
        assert!(plaintexts.iter().any(|val| val == &BigUint::one()));
        assert!(plaintexts.iter().any(|val| val == &BigUint::from(2u32)));
        assert!(plaintexts.iter().any(|val| val == &BigUint::from(3u32)));
    }

    #[test]
    fn it_should_verify_decryption_proof_multiple_partial_decryptions_encoded() {
        // create system parameters
        let params = ElGamalParams {
            // 48bit key -> sm_system
            p: BigUint::parse_bytes(b"B7E151629927", 16).unwrap(),
            g: BigUint::parse_bytes(b"4", 10).unwrap(),
            h: BigUint::parse_bytes(b"9", 10).unwrap(),
        };
        let q = &params.q();

        // create bob's public and private key
        let bob_id = "Bob".as_bytes();
        let bob_sk_x = Random::get_random_less_than(q);
        let (bob_pk, bob_sk) = Helper::generate_key_pair(&params, &bob_sk_x);

        // create charlie's public and private key
        let charlie_id = "Charlie".as_bytes();
        let charlie_sk_x = Random::get_random_less_than(q);
        let (charlie_pk, charlie_sk) = Helper::generate_key_pair(&params, &charlie_sk_x);

        // create common public key
        let combined_pk = PublicKey {
            h: bob_pk.h.modmul(&charlie_pk.h, &bob_pk.params.p),
            params: params.clone(),
        };

        let start = Instant::now();

        // get three encrypted values: 0, 1, 2 using the generated common public key
        let encryptions = Random::generate_random_encryptions_encoded(&combined_pk, q, 3);

        let duration = start.elapsed();
        println!(
            "duration generate_random_encryptions ENCODED: {:?}",
            duration
        );

        // get bob's partial decryptions
        let bob_partial_decrytpions = encryptions
            .iter()
            .map(|cipher| ElGamal::partial_decrypt_a(cipher, &bob_sk))
            .collect::<Vec<BigUint>>();

        let duration = start.elapsed();
        println!("duration bob_partial_decrytpions ENCODED: {:?}", duration);

        // create bob's proof
        let r = Random::get_random_less_than(q);
        let bob_proof = DecryptionProof::generate(
            &params,
            &bob_sk.x,
            &bob_pk.h,
            &r,
            encryptions.clone(),
            bob_partial_decrytpions.clone(),
            bob_id,
        );

        let duration = start.elapsed();
        println!("duration DecryptionProof::generate ENCODED: {:?}", duration);

        // verify that bob's proof is correct
        let bob_proof_is_correct = DecryptionProof::verify(
            &params,
            &bob_pk.h,
            &bob_proof,
            encryptions.clone(),
            bob_partial_decrytpions.clone(),
            bob_id,
        );
        assert!(bob_proof_is_correct);
        let duration = start.elapsed();
        println!("duration DecryptionProof::verify ENCODED: {:?}", duration);

        // get charlie's partial decryptions
        let charlie_partial_decrytpions = encryptions
            .iter()
            .map(|cipher| ElGamal::partial_decrypt_a(cipher, &charlie_sk))
            .collect::<Vec<BigUint>>();
        let duration = start.elapsed();
        println!(
            "duration charlie_partial_decrytpions ENCODED: {:?}",
            duration
        );

        // create charlie's proof
        let r = Random::get_random_less_than(q);
        let charlie_proof = DecryptionProof::generate(
            &params,
            &charlie_sk.x,
            &charlie_pk.h,
            &r,
            encryptions.clone(),
            charlie_partial_decrytpions.clone(),
            charlie_id,
        );
        let duration = start.elapsed();
        println!("duration DecryptionProof::generate ENCODED: {:?}", duration);

        // verify that charlie's proof is correct
        let charlie_proof_is_correct = DecryptionProof::verify(
            &params,
            &charlie_pk.h,
            &charlie_proof,
            encryptions.clone(),
            charlie_partial_decrytpions.clone(),
            charlie_id,
        );
        assert!(charlie_proof_is_correct);
        let duration = start.elapsed();
        println!("duration DecryptionProof::verify ENCODED: {:?}", duration);

        // combine partial decrypted components a
        let combined_decryptions = ElGamal::combine_partial_decrypted_as(
            vec![bob_partial_decrytpions, charlie_partial_decrytpions],
            &params.p,
        );
        let duration = start.elapsed();
        println!(
            "duration combine_partial_decrypted_as ENCODED: {:?}",
            duration
        );

        // retrieve the plaintext votes
        // by combining the decrypted components a with their decrypted components b
        let iterator = encryptions.iter().zip(combined_decryptions.iter());
        let plaintexts = iterator
            .map(|(cipher, decrypted_a)| {
                ElGamal::partial_decrypt_b(&cipher.b, decrypted_a, &params.p)
            })
            .collect::<Vec<BigUint>>();
        let duration = start.elapsed();
        println!("duration partial_decrypt_b ENCODED: {:?}", duration);

        // the votes are still encoded g^m at this point
        // decode the decrypted votes in the following step
        let plaintexts = plaintexts
            .iter()
            .map(|encoded| ElGamal::decode_message(encoded, &params.g, &params.p))
            .collect::<Vec<BigUint>>();
        let duration = start.elapsed();
        println!("duration decode_message ENCODED: {:?}", duration);

        // check that at least one value is 0, 1, 2
        assert!(plaintexts.len() == 3, "there should be three plaintexts");
        assert!(plaintexts.iter().any(|val| val == &BigUint::zero()));
        assert!(plaintexts.iter().any(|val| val == &BigUint::one()));
        assert!(plaintexts.iter().any(|val| val == &BigUint::from(2u32)));
    }
}
