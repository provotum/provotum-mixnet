use crate::{Error, Module, Trait};
use crypto::{
    helper::Helper,
    proofs::ShuffleProof,
    types::{Cipher, ModuloOperations, PublicKey},
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sp_std::{if_std, vec::Vec};

/// all functions related to zero-knowledge proofs in the offchain worker
impl<T: Trait> Module<T> {
    /// GenShuffleProof Algorithm 8.47 (CHVoteSpec 3.1)
    ///
    /// Generates a shuffle proof relative to encryptions e and e_tilde, which
    /// is equivalent to proving knowledge of a permutation and randomizations
    /// The algorithm implements Wikström’s proof of a shuffle
    /// except for the fact that the offline and online phases are merged.
    pub fn generate_shuffle_proof(
        id: usize,
        encryptions: Vec<Cipher>,
        shuffled_encryptions: Vec<Cipher>,
        re_encryption_randoms: Vec<BigUint>,
        permutation: &[usize],
        pk: &PublicKey,
    ) -> Result<
        (
            BigUint, // challenge
            (
                BigUint,      // s1
                BigUint,      // s2
                BigUint,      // s3
                BigUint,      // s4
                Vec<BigUint>, // vec_s_hat
                Vec<BigUint>, // vec_s_tilde
            ),
            Vec<BigUint>, // permutation_commitments
            Vec<BigUint>, // permutation_chain_commitments
        ),
        Error<T>,
    > {
        // input checks
        assert!(
            encryptions.len() == shuffled_encryptions.len(),
            "encryptions and shuffled_encryptions need to have the same length!"
        );
        assert!(
            encryptions.len() == re_encryption_randoms.len(),
            "encryptions and re_encryption_randoms need to have the same length!"
        );
        assert!(
            encryptions.len() == permutation.len(),
            "encryptions and permutation need to have the same length!"
        );
        assert!(!encryptions.is_empty(), "vectors cannot be empty!");

        // the size of the shuffle (# of encrypted votes)
        let size = encryptions.len();
        let params = &pk.params;
        let q = &params.q();
        let e = encryptions;
        let e_tilde = shuffled_encryptions;
        let vec_r_tilde = re_encryption_randoms;

        // get {size} independent generators: h
        let vec_h = Helper::get_generators(id, q, size);

        // commit to the given permutation: (vec_c, vec_r)
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;
        let permutation_commitment = ShuffleProof::generate_permutation_commitment(
            params,
            permutation,
            randoms.clone(),
            vec_h.clone(),
        );
        let vec_c = permutation_commitment.commitments;
        let vec_r = permutation_commitment.randoms;

        // get {size} challenges
        // vec_u = get_challenges(size, hash(e, e_tilde, vec_c, pk))
        let vec_u =
            ShuffleProof::get_challenges(size, e.clone(), e_tilde.clone(), vec_c.clone(), pk);

        // permute the challenges -> same order as randoms + permuation
        let u_tilde = Self::permute_vector(vec_u.clone(), permutation);

        // generate commitment chain: (vec_c_hat, vec_r_hat)
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;

        // (vector_c_hat, vector_r_hat) = GenCommitmentChain(vector_u_tilde)
        // vector_u_tilde = challenges, re-ordered according to the permutation
        let commitment_chain =
            ShuffleProof::generate_commitment_chain(u_tilde.clone(), randoms, params);
        let vec_c_hat = commitment_chain.commitments;
        let vec_r_hat = commitment_chain.randoms;

        // generate t & w values
        let (t1, t2, t3, (t4_1, t4_2), vec_t_hat, w1, w2, w3, w4, vec_w_hat, vec_w_tilde) =
            Self::generate_t_and_w_values(
                vec_r_hat.clone(),
                u_tilde.clone(),
                vec_h.clone(),
                e_tilde.clone(),
                pk,
                size,
            )?;

        if_std! {
            // println!("prover - \n t4_1: {:?},\n t4_2: {:?}\n", t4_1, t4_2);
            // println!("prover - t3: {:?}", t3);
            // println!("prover - \n vec_t_hat: {:?}\n", vec_t_hat);
            // println!("prover - vec_h: {:?}\n", vec_h);
        }

        // generate challenge from (y, t)
        // public value y = ((e, e_tilde, vec_c, vec_c_hat, pk)
        // public commitment t = (t1, t2, t3, (t4_1, t4_2), (t_hat_0, ..., t_hat_(size-1)))
        let public_value = (e, e_tilde, vec_c.clone(), vec_c_hat.clone(), pk);
        let public_commitment = (
            t1.clone(),
            t2.clone(),
            t3.clone(),
            (t4_1.clone(), t4_2.clone()),
            vec_t_hat.clone(),
        );
        let challenge = ShuffleProof::get_challenge(public_value, public_commitment);

        // generate s values
        // s = (s1, s2, s3, s4, (s_hat_0, ..., s_hat_(size-1)), (s_tilde_0, ..., s_tilde_(size-1)))
        let (s1, s2, s3, s4, vec_s_hat, vec_s_tilde) = Self::generate_s_values(
            &challenge,
            q,
            vec_r,
            vec_r_hat,
            vec_r_tilde,
            w1,
            w2,
            w3,
            w4,
            vec_w_hat,
            vec_w_tilde,
            vec_u,
            u_tilde,
            size,
        );
        let s = (
            s1,
            s2,
            s3,
            s4.clone(),
            vec_s_hat.clone(),
            vec_s_tilde.clone(),
        );
        // return (challenge, s, permutation_commitments, chain_commitments)
        Ok((challenge, s, vec_c, vec_c_hat))
    }

    fn generate_s_values(
        challenge: &BigUint,
        q: &BigUint,
        vec_r: Vec<BigUint>,
        vec_r_hat: Vec<BigUint>,
        vec_r_tilde: Vec<BigUint>,
        w1: BigUint,
        w2: BigUint,
        w3: BigUint,
        w4: BigUint,
        vec_w_hat: Vec<BigUint>,
        vec_w_tilde: Vec<BigUint>,
        vec_u: Vec<BigUint>,
        u_tilde: Vec<BigUint>,
        size: usize,
    ) -> (
        BigUint,      // s1
        BigUint,      // s2
        BigUint,      // s3
        BigUint,      // s4
        Vec<BigUint>, // vec_s_hat
        Vec<BigUint>, // vec_s_tilde
    ) {
        // get r_flat
        // Σ(r_i) mod q where r_i are the random values from the permutation commitment
        let r_flat = vec_r
            .iter()
            .fold(BigUint::zero(), |sum, r| sum.modadd(r, q));

        // get s1 = (w1 - challenge * r_flat) % q
        // we add q to w1 to ensure the value will always be >0
        let s1 = w1.modsub(&challenge.modmul(&r_flat, q), q);

        // generate v values from (N-1...0)
        // start with value v_(n-1) = 1
        let mut v = Vec::new();
        let mut v_i = BigUint::one();
        v.push(v_i.clone());

        // v_(n-1) = 1
        // for i = N-2..0 do
        for i in (0..(size - 1)).rev() {
            //
            let u_tilde_i = &u_tilde[i + 1];

            // v_(i-1) = u_tilde_i * v_i mod q
            v_i = u_tilde_i.modmul(&v_i, q);
            v.push(v_i.clone());
        }

        // reverse the order in v
        v.reverse();

        // get r values
        // vec_r_hat -> random values of commitment chain
        // get r_hat = Σ(vec_r_hat_i * v_i) mod q
        let r_hat = Self::zip_vectors_sum_products(&vec_r_hat, &v, q);

        // we add q to w2 to ensure the value will always be >0
        // s2 = w2 - challenge * r_hat % q
        let s2 = w2.modsub(&challenge.modmul(&r_hat, q), q);

        // vec_r -> random values of permutation commitment
        // get r = Σ(vec_r_i * u_i) mod q
        let r = Self::zip_vectors_sum_products(&vec_r, &vec_u, q);

        // we add q to w3 to ensure the value will always be >0
        // s3 = w3 - challenge * r % q
        let s3 = w3.modsub(&challenge.modmul(&r, q), q);

        if_std! {
            // println!("prover - vec_r: {:?}\n", vec_r);
            // println!("prover - vec_u: {:?}, length: {:?}\n", vec_u, vec_u.len());
            // println!("prover - r: {:?}\n", r);
            // println!("prover - w3: {:?}, challenge: {:?}, s3: {:?}\n", w3, challenge, s3);
        }

        // vec_r_tilde -> random values of re-encryption
        // get r_tilde
        let r_tilde = Self::zip_vectors_sum_products(&vec_r_tilde, &vec_u, q);

        // we add q to w4 to ensure the value will always be >0
        let s4 = w4.modsub(&challenge.modmul(&r_tilde, q), q);

        // generate vec_s_hat & vec_s_tilde values
        let mut vec_s_hat = Vec::new();
        let mut vec_s_tilde = Vec::new();
        for i in 0..size {
            let w_hat_i = &vec_w_hat[i];
            let r_hat_i = &vec_r_hat[i];

            // s_hat_i = w_hat_i - challenge * r_hat_i mod q
            // we add q to w_hat_i to ensure the value will always be >0
            let c_r_hat_i = challenge.modmul(r_hat_i, q);
            let s_hat_i = w_hat_i.modsub(&c_r_hat_i, q);
            vec_s_hat.push(s_hat_i);

            let w_tilde_i = &vec_w_tilde[i];
            let u_tilde_i = &u_tilde[i];

            // s_tilde_i = w_tilde_i - challenge * u_tilde_i mod q
            // we add q to w_tilde_i to ensure the value will always be >0
            let c_u_tilde_i = challenge.modmul(u_tilde_i, q);
            let s_tilde_i = w_tilde_i.modsub(&c_u_tilde_i, q);
            vec_s_tilde.push(s_tilde_i);
        }
        (s1, s2, s3, s4, vec_s_hat, vec_s_tilde)
    }

    fn generate_t_and_w_values(
        r_hat: Vec<BigUint>,
        u_tilde: Vec<BigUint>,
        vec_h: Vec<BigUint>,
        shuffled_encryptions: Vec<Cipher>,
        public_key: &PublicKey,
        size: usize,
    ) -> Result<
        (
            BigUint,            // t1
            BigUint,            // t2
            BigUint,            // t3
            (BigUint, BigUint), // (t4_1, t4_2)
            Vec<BigUint>,       // vec_t_hat
            BigUint,            // w1
            BigUint,            // w2
            BigUint,            // w3
            BigUint,            // w4
            Vec<BigUint>,       // vec_w_hat
            Vec<BigUint>,       // vec_w_tilde
        ),
        Error<T>,
    > {
        let pk = &public_key.h;
        let p = &public_key.params.p;
        let q = &public_key.params.q();
        let g = &public_key.params.g;
        let h = &public_key.params.h;

        let mut r_i = BigUint::zero();
        let mut r_i_dash: BigUint;
        let mut u_i = BigUint::one();
        let mut u_i_dash: BigUint;
        let mut t_hat_i: BigUint;
        let mut vec_t_hat: Vec<BigUint> = Vec::new();

        // get random values
        let vec_w_tilde: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;
        let vec_w_hat: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;

        // part 1: generate vec_t_hat & vec_w_tilde values
        for i in 0..size {
            let w_hat_i = &vec_w_hat[i];
            let w_tilde_i = &vec_w_tilde[i];

            // get random value r_hat_i used during commitment chain generation
            let r_hat_i = &r_hat[i];

            // get challenge value u_tilde_i
            let u_tilde_i = &u_tilde[i];

            // r_i_dash = w_hat_i + w_tilde_i * r_(i-1) mod q
            r_i_dash = w_hat_i.modadd(&w_tilde_i.modmul(&r_i, q), q);

            // r_i = r_hat_i + u_tilde_i * r_(i-1) mod q
            r_i = r_hat_i.modadd(&u_tilde_i.modmul(&r_i, q), q);

            // u_i_dash = w_tilde_i * u_(i-1) mod q
            u_i_dash = w_tilde_i.modmul(&u_i, q);

            // u_i = u_tilde_i * u_(i-1) mod q
            u_i = u_tilde_i.modmul(&u_i, q);

            // t_hat_i = g^r_i_dash * h_u_i_dash mod p
            let g_r_i_dash = g.modpow(&r_i_dash, p);
            let h_u_i_dash = h.modpow(&u_i_dash, p);
            t_hat_i = g_r_i_dash.modmul(&h_u_i_dash, p);
            vec_t_hat.push(t_hat_i);
        }

        // part 2: generate t1, t2, t3 & w1, w2, w3, w4 values
        let w1 = Self::get_random_biguint_less_than(q)?;
        let w2 = Self::get_random_biguint_less_than(q)?;
        let w3 = Self::get_random_biguint_less_than(q)?;
        let w4 = Self::get_random_biguint_less_than(q)?;

        let t1 = g.modpow(&w1, p);
        let t2 = g.modpow(&w2, p);

        // t3 = g^w3 * Π(h_i^w_tilde_i) % p
        let g_pow_w3 = g.modpow(&w3, p);

        // prod = Π(h_i^w_tilde_i) % p
        let prod = Self::zip_vectors_multiply_a_pow_b(&vec_h, &vec_w_tilde, p);
        let t3 = g_pow_w3.modmul(&prod, p);

        if_std! {
            // println!("prover - vec_h: {:?}\n", vec_h);
            // println!("prover - vec_w_tilde: {:?}\n", vec_w_tilde);
            // println!("prover - g: {:?}, w3: {:?}, g: {:?}\n", g, w3, g_pow_w3);
        }

        // chain with shuffled encryptions
        // generate t4_1, t4_2

        // g is the first public generator
        // g^-w4 = (g^-1)^w4 = (g^w4)^-1 = invmod(g^w4)
        // for an explanation see: Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) page 9
        let g_pow_w4 = g.modpow(&w4, p);
        let inv_g_pow_w4 = g_pow_w4.invmod(p).ok_or_else(|| Error::InvModError)?;

        let vec_a_tilde: Vec<BigUint> = shuffled_encryptions
            .clone()
            .into_iter()
            .map(|c| c.a)
            .collect();
        let prod_a_tilde_w_tilde =
            Self::zip_vectors_multiply_a_pow_b(&vec_a_tilde, &vec_w_tilde, p);
        let t4_1 = inv_g_pow_w4.modmul(&prod_a_tilde_w_tilde, p);

        // pk is the public key
        // pk^-w4 = (pk^-1)^w4 = invmod(pk)^w4 mod p
        // for an explanation see: Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) page 9
        let inv_pk = pk.invmod(p).ok_or_else(|| Error::InvModError)?;
        let inv_pk_pow_w4 = inv_pk.modpow(&w4, p);
        let vec_b_tilde: Vec<BigUint> = shuffled_encryptions.into_iter().map(|c| c.b).collect();
        let prod_b_tilde_w_tilde =
            Self::zip_vectors_multiply_a_pow_b(&vec_b_tilde, &vec_w_tilde, p);
        let t4_2 = inv_pk_pow_w4.modmul(&prod_b_tilde_w_tilde, p);

        Ok((
            t1,
            t2,
            t3,
            (t4_1, t4_2),
            vec_t_hat,
            w1,
            w2,
            w3,
            w4,
            vec_w_hat,
            vec_w_tilde,
        ))
    }
}
