use crate::{
    encryption::ElGamal,
    helper::Helper,
    types::{Cipher, ModuloOperations, PublicKey},
};
use num_bigint::BigUint;
use num_traits::One;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct ReEncryptionProof {
    pub c_one_prime: Cipher,
    pub challenge: BigUint,
    pub h1: BigUint,
    pub h2: BigUint,
    pub s2: BigUint,
    pub t2: BigUint,
}

/// Implements a designated verifier zero-knowledge proof
/// for a multiplicative ElGamal re-encryption
impl ReEncryptionProof {
    /// Comment this function
    pub fn generate(
        r1: &BigUint, // random value r1 that was used to re_encrypt
        r2: &BigUint,
        h2: &BigUint,
        s2: &BigUint,
        c_one: &Cipher, // publicly known encryption of 1 using r1
        pk: &PublicKey,
    ) -> ReEncryptionProof {
        // common parameters
        let p = &pk.params.p;
        let q = &pk.params.q();
        let g = &pk.params.g;
        let h = &pk.h;

        // compute new random encryption of one
        let one = BigUint::one();
        let c_one_prime = ElGamal::encrypt(&one, r2, pk);

        // generate the commitment
        // t2 = g^s2 * pk^-h2 mod p = g^s2 / pk^h2 mod p
        let g_pow_s2 = g.modpow(s2, p);
        let pk_pow_h2 = h.modpow(h2, p);
        let t2 = g_pow_s2
            .moddiv(&pk_pow_h2, p)
            .expect("cannot compute mod_inverse in mod_div!");

        // generate the challenge -> hash the commitment + the public values
        let mut h =
            Helper::hash_re_encryption_proof_inputs("re_encryption", c_one, &c_one_prime, &t2);
        h %= q;

        // split the hash into two parts h1 = h - h2
        let h1 = h.modsub(h2, q);

        // compute the challenge
        let challenge = h1.modmul(r1, q).modadd(r2, q);
        ReEncryptionProof {
            c_one_prime,
            challenge,
            h1,
            h2: h2.clone(),
            s2: s2.clone(),
            t2,
        }
    }

    /// Comment this Function
    pub fn verify(
        pk: &PublicKey,
        proof: &ReEncryptionProof,
        cipher: &Cipher,
        re_enc_cipher: &Cipher,
    ) -> bool {
        // common parameters
        let p = &pk.params.p;
        let g = &pk.params.g;
        let q = &pk.params.q();

        // deconstruct the proof
        let challenge = &proof.challenge;
        let c_one_prime = &proof.c_one_prime;
        let h1 = &proof.h1;
        let h2 = &proof.h2;
        let s2 = &proof.s2;
        let t2 = &proof.t2;

        // recompute c_one -> publicly known encryption of 1 using r1
        // by homomorphically subtracting the re-encryption from the original ballot
        // in a multiplicative homomorphic ElGamal encryption this results in a division
        let c_one = ElGamal::homomorphic_subtraction(re_enc_cipher, cipher, p);

        // recompute the hash
        let mut h_prime =
            Helper::hash_re_encryption_proof_inputs("re_encryption", &c_one, c_one_prime, t2);
        h_prime %= q;

        // add the two hash parts from the prover
        let h = h1.modadd(h2, q);

        // verify that the hashes are the same
        let v1 = h_prime == h;

        // verify the commitment: E(1,challenge) = h1 * c_one homomorphic_addition c_one_prime
        // 1. compute the left hand side E(1,challenge)
        let one = BigUint::one();
        let lhs = ElGamal::encrypt(&one, challenge, pk);

        // 2. compute the right hand side h1 * c_one homomorphic_addition c_one_prime
        let h1_c_one = ElGamal::homomorphic_multiply(&c_one, h1, p);
        let rhs = ElGamal::homomorphic_addition(&h1_c_one, c_one_prime, p);

        // verify that lhs == rhs
        let v2 = lhs == rhs;

        // 3. test: verify that g^s2 == pk^c2 * t2
        let lhs = g.modpow(s2, p);
        let pk_pow_h2 = pk.h.modpow(h2, p);
        let rhs = pk_pow_h2.modmul(t2, p);

        // verify that lhs == rhs
        let v3 = lhs == rhs;

        // the proof is correct if all three checks pass
        v1 && v2 && v3
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encryption::ElGamal, helper::Helper, proofs::re_encryption::ReEncryptionProof,
        random::Random,
    };
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    fn it_should_verify_re_encryption_proofs() {
        // test setup
        let (params, _, pk) = Helper::setup_sm_system();
        let q = &params.q();

        // chose a number of random votes
        let votes = vec![
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(3u32),
            BigUint::from(13u32),
        ];

        for vote in votes {
            // 1. the voter encrypts his vote
            let r0 = Random::get_random_less_than(q);
            let ballot = ElGamal::encrypt(&vote, &r0, &pk);

            // 2. the randomizer re-encrypts the ballot
            let r1 = Random::get_random_less_than(q);
            let ballot_prime = ElGamal::re_encrypt(&ballot, &r1, &pk);

            // 3. the randomizer generates a proof to show that the re-encryption is valid
            // 3.1 generate c_one -> the encryption of 1 using the re-encryption random r1
            let one = BigUint::one();
            let c_one = ElGamal::encrypt(&one, &r1, &pk);

            // 3.2 generate the proof
            let r2 = Random::get_random_less_than(q);
            let h2 = Random::get_random_less_than(q);
            let s2 = Random::get_random_less_than(q);
            let proof = ReEncryptionProof::generate(&r1, &r2, &h2, &s2, &c_one, &pk);

            // 4. the voter verifies the re-encryption proof
            let proof_is_valid = ReEncryptionProof::verify(&pk, &proof, &ballot, &&ballot_prime);
            assert!(proof_is_valid);
        }
    }
}
