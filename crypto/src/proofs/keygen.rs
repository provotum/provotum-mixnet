use crate::{
    helper::Helper,
    types::{ElGamalParams, ModuloOperations},
};
use num_bigint::BigUint;

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub struct KeyGenerationProof {
    pub challenge: BigUint,
    pub response: BigUint,
}

impl KeyGenerationProof {
    /// Generates a proof of knowledge of a secret key (sk) that belongs to a public key (pk = g^sk) using the Schnorr protocol. It is a proof of knowledge of a discrete logarithm of x = log_g(g^x).
    ///
    /// Step by Step:
    /// 1. generate a "second" key pair (a,b) = (random value from Z_q, g^a mod p)
    /// 2. compute challenge
    /// 3. compute d = a + c*sk
    pub fn generate(
        params: &ElGamalParams,
        sk: &BigUint,
        pk_share: &BigUint,
        r: &BigUint,
        id: &[u8],
    ) -> KeyGenerationProof {
        // system parameters
        let g = &params.g;
        let q = &params.q();
        let p = &params.p;

        // the public key
        let h = pk_share;

        // the private key
        let x = sk;

        // the commitment
        let a = r;
        let b = &g.modpow(r, p);

        // compute challenge -> hash public values (hash(unique_id, h, b) mod q)
        let mut c = Helper::hash_key_gen_proof_inputs(id, "keygen", h, b);
        c %= q;

        // compute the response
        let d = a.modadd(&c.modmul(x, q), q);

        KeyGenerationProof {
            challenge: c,
            response: d,
        }
    }

    /// Verifies a proof of knowledge of a secret key (sk) that belongs to a public key (pk = g^sk) using the Schnorr protocol. It is a proof of knowledge of a discrete logarithm of x = log_g(g^x).
    ///
    /// Step by Step:
    /// 1. recompute b = g^d/h^c
    /// 2. recompute the challenge c
    /// 3. verify that the challenge is correct
    /// 4. verify that: g^d == b * h^c
    pub fn verify(
        params: &ElGamalParams,
        pk_share: &BigUint,
        proof: &KeyGenerationProof,
        id: &[u8],
    ) -> bool {
        // system parameters
        let g = &params.g;
        let q = &params.q();
        let p = &params.p;

        // the public key
        let h = pk_share;

        // the proof
        let c = &proof.challenge;
        let d = &proof.response;

        // recompute b
        let g_pow_d = g.modpow(d, p);
        let h_pow_c = h.modpow(c, p);
        let b = g_pow_d
            .moddiv(&h_pow_c, p)
            .expect("cannot compute mod_inverse in mod_div!");

        // recompute the hash
        let mut c_ = Helper::hash_key_gen_proof_inputs(id, "keygen", h, &b);
        c_ %= q;

        // verify that the challenges are the same
        let v1 = *c == c_;

        // verify that the responses are the same
        let v2 = g_pow_d == b.modmul(&h_pow_c, p);

        v1 && v2
    }
}

#[cfg(test)]
mod tests {
    use crate::{helper::Helper, proofs::keygen::KeyGenerationProof, random::Random};
    use num_bigint::BigUint;

    #[test]
    fn it_should_create_keygen_proof_tiny() {
        let sealer_id = "Bob".as_bytes();
        let (params, sk, pk) = Helper::setup_tiny_system();
        let r = BigUint::parse_bytes(b"B", 16).unwrap();

        let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, sealer_id);
        assert_eq!(proof.challenge, BigUint::from(15u32));
        assert_eq!(proof.response, BigUint::from(13u32));
    }

    #[test]
    fn it_should_verify_keygen_proof() {
        let sealer_id = "Charlie".as_bytes();
        let (params, sk, pk) = Helper::setup_sm_system();
        let r = Random::get_random_less_than(&params.q());

        let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, sealer_id);

        // verify the proof
        let is_verified = KeyGenerationProof::verify(&params, &pk.h, &proof, sealer_id);
        assert!(is_verified);
    }
}
