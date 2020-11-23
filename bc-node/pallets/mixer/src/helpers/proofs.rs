use crate::{Error, Module, Trait};
use crypto::{
    helper::Helper,
    proofs::ShuffleProof,
    types::{Cipher, ModuloOperations, PublicKey},
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sp_std::vec::Vec;

/// all functions related to zero-knowledge proofs in the offchain worker
impl<T: Trait> Module<T> {
    /// GenShuffleProof Algorithm 8.47 (CHVoteSpec 3.1)
    ///
    /// Generates a shuffle proof relative to encryptions e and e_hat, which
    /// is equivalent to proving knowledge of a permutation and randomizations
    /// The algorithm implements Wikström’s proof of a shuffle
    /// except for the fact that the offline and online phases are merged.
    pub fn shuffle_proof(
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
                Vec<BigUint>, // s_hat
                Vec<BigUint>, // s_tilde
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
        let g = &params.g;
        let h = &params.h;
        let q = &params.q();
        let e = encryptions;
        let e_hat = shuffled_encryptions;
        let vec_r_tilde = re_encryption_randoms;

        // get {size} independent generators: h
        let generators = Helper::get_generators(id, q, size);

        // commit to the given permutation: (c, r)
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;
        let permutation_commitment = ShuffleProof::generate_permutation_commitment(
            params,
            permutation,
            randoms,
            generators.clone(),
        );
        let c = permutation_commitment.commitments;
        let vec_r = permutation_commitment.randoms;

        // get {size} challenges
        // u_tilde = get_challenges(size, hash(e, e_hat, c, pk))
        let u =
            ShuffleProof::get_challenges(size, e.clone(), e_hat.clone(), c.clone(), pk);
        // permute the challenges -> same order as randoms + permuation
        let u_tilde = Self::permute_vector(u.clone(), permutation);

        // generate commitment chain: (c_hat, r_hat)
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;

        // (vector_c_hat, vector_r_hat) = GenCommitmentChain(vector_u_tilde)
        // vector_u_tilde = challenges, re-ordered according to the permutation
        let commitment_chain =
            ShuffleProof::generate_commitment_chain(u_tilde.clone(), randoms, params);
        let c_hat = commitment_chain.commitments;
        let vec_r_hat = commitment_chain.randoms;

        // generate t & w values
        let (t1, t2, t3, (t4_1, t4_2), t_hat, w1, w2, w3, w4, w_hat, w_tilde) =
            Self::generate_t_and_w_values(
                vec_r_hat.clone(),
                u_tilde.clone(),
                generators,
                e_hat.clone(),
                pk,
                size,
            )?;

        // generate challenge from (y, t)
        // public value y = ((e, e_hat, c, c_hat, pk)
        // public commitment t = (t1, t2, t3, (t4_1, t4_2), (t_hat_0, ..., t_hat_(size-1)))
        let public_value = (e, e_hat, c.clone(), c_hat.clone(), pk);
        let public_commitment = (t1, t2, t3, (t4_1, t4_2), t_hat);
        let challenge = ShuffleProof::get_challenge(public_value, public_commitment);

        // generate s values
        // s = (s1, s2, s3, s4, (s_hat_0, ..., s_hat_(size-1)), (s_tilde_0, ..., s_tilde_(size-1)))
        let (s1, s2, s3, s4, s_hat, s_tilde) = Self::generate_s_values(
            &challenge,
            q,
            vec_r,
            vec_r_hat,
            vec_r_tilde,
            w1,
            w2,
            w3,
            w4,
            w_hat,
            w_tilde,
            u,
            u_tilde,
            size,
        );
        let s = (s1, s2, s3, s4, s_hat, s_tilde);

        // return (challenge, s, permutation_commitments, chain_commitments)
        Ok((challenge, s, c, c_hat))
    }

    fn zip_and_fold(vec1: Vec<BigUint>, vec2: Vec<BigUint>, q: &BigUint) -> BigUint {
        let iterator = vec1.iter().zip(vec2.iter());
        let value = iterator.fold(BigUint::zero(), |sum, (a, b)| sum + a * b);
        value % q
    }

    pub fn generate_s_values(
        c: &BigUint,
        q: &BigUint,
        vec_r: Vec<BigUint>,
        vec_r_hat: Vec<BigUint>,
        vec_r_tilde: Vec<BigUint>,
        w1: BigUint,
        w2: BigUint,
        w3: BigUint,
        w4: BigUint,
        w_hat: Vec<BigUint>,
        w_tilde: Vec<BigUint>,
        u: Vec<BigUint>,
        u_tilde: Vec<BigUint>,
        size: usize,
    ) -> (
        BigUint,      // s1
        BigUint,      // s2
        BigUint,      // s3
        BigUint,      // s4
        Vec<BigUint>, // s_hat
        Vec<BigUint>, // s_tilde
    ) {
        // get r_flat
        // sum(r_i) mod q where r_i are the random values from the permutation commitment
        let r_flat = vec_r
            .iter()
            .fold(BigUint::zero(), |sum, r| sum.modadd(r, q));

        // get s1 = (w1 - c * r_flat) mod q
        // we add q to w1 to ensure the value will always be >0
        let s1 = ((q + w1) - c.modmul(&r_flat, q)) % q;

        // generate v values from (N-1...0)
        // start with value v_(n-1) = 1
        let mut v = Vec::new();
        let v_i = BigUint::one();
        v.push(v_i.clone());

        for i in (0..size).rev() {
            let u_tilde_i = &u_tilde[i];

            // v_(i-1) = u_tilde_i * v_i mod q
            let v_i = u_tilde_i.modmul(&v_i, q);
            v.push(v_i.clone());
        }

        // TODO: check if this is necessary
        // reverse the order in v
        v.reverse();

        // get r values
        // vec_r_hat -> random values of commitment chain
        // get r_hat = sum(vec_r_hat_i * v_i) mod q
        let r_hat = Self::zip_and_fold(vec_r_hat.clone(), v, q);

        // we add q to w2 to ensure the value will always be >0
        let s2 = ((q + w2) - c.modmul(&r_hat, q)) % q;

        // vec_r -> random values of permutation commitment
        // get r = sum(vec_r_i * u_i) mod q
        let r = Self::zip_and_fold(vec_r, u.clone(), q);

        // we add q to w3 to ensure the value will always be >0
        let s3 = ((q + w3) - c.modmul(&r, q)) % q;

        // vec_r_tilde -> random values of re-encryption
        // get r_tilde
        let r_tilde = Self::zip_and_fold(vec_r_tilde, u, q);

        // we add q to w4 to ensure the value will always be >0
        let s4 = ((q + w4) - c.modmul(&r_tilde, q)) % q;

        // generate s_hat & s_tilde values
        let mut s_hat = Vec::new();
        let mut s_tilde = Vec::new();
        for i in 0..size {
            let w_hat_i = &w_hat[i];
            let r_hat_i = &vec_r_hat[i];

            // s_hat_i = w_hat_i - c * r_hat_i mod q
            // we add q to w_hat_i to ensure the value will always be >0
            let s_hat_i = ((q + w_hat_i) - c.modmul(r_hat_i, q)) % q;
            s_hat.push(s_hat_i);

            let w_tilde_i = &w_tilde[i];
            let u_tilde_i = &u_tilde[i];

            // s_tilde_i = w_tilde_i - c * u_tilde_i mod q
            // we add q to w_tilde_i to ensure the value will always be >0
            let s_tilde_i = ((q + w_tilde_i) - c.modmul(u_tilde_i, q)) % q;
            s_tilde.push(s_tilde_i);
        }
        (s1, s2, s3, s4, s_hat, s_tilde)
    }

    pub fn generate_t_and_w_values(
        r_hat: Vec<BigUint>,
        u_tilde: Vec<BigUint>,
        generators: Vec<BigUint>,
        shuffled_encryptions: Vec<Cipher>,
        public_key: &PublicKey,
        size: usize,
    ) -> Result<
        (
            BigUint,            // t1
            BigUint,            // t2
            BigUint,            // t3
            (BigUint, BigUint), // (t4_1, t4_2)
            Vec<BigUint>,       // t_hat
            BigUint,            // w1
            BigUint,            // w2
            BigUint,            // w3
            BigUint,            // w4
            Vec<BigUint>,       // w_hat
            Vec<BigUint>,       // w_tilde
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
        let mut w_tilde: Vec<BigUint> = Vec::new();
        let mut w_hat: Vec<BigUint> = Vec::new();
        let mut t_hat: Vec<BigUint> = Vec::new();

        // part 1: generate t_hat & w_tilde values

        for i in 0..size {
            let w_hat_i = Self::get_random_biguint_less_than(q)?;
            let w_tilde_i = Self::get_random_biguint_less_than(q)?;
            w_hat.push(w_hat_i.clone());
            w_tilde.push(w_tilde_i.clone());

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
            t_hat.push(t_hat_i);
        }

        // part 2: generate t1, t2, t3 & w1, w2, w3, w4 values

        let w1 = Self::get_random_biguint_less_than(q)?;
        let w2 = Self::get_random_biguint_less_than(q)?;
        let w3 = Self::get_random_biguint_less_than(q)?;
        let w4 = Self::get_random_biguint_less_than(q)?;

        let t1 = g.modpow(&w1, p);
        let t2 = g.modpow(&w2, p);

        let mut t3 = g.modpow(&w3, p);

        for i in 0..size {
            let w_tilde_i = &w_tilde[i];
            let generator = &generators[i];
            t3 *= generator.modpow(w_tilde_i, p);
        }
        t3 %= p;

        // chain with shuffled encryptions
        // generate t4_1, t4_2
        // pk is the public key
        // pk^-w4 = (pk^-1)^w4 = (pk^w4)^-1 = invmod(pk^w4)
        // for an explanation see: Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) page 9
        let mut t4_1 = pk.modpow(&w4, p);
        t4_1 = t4_1.invmod(p).ok_or_else(|| Error::InvModError)?;

        // g is the first public generator
        // g^-w4 = (g^-1)^w4 = (g^w4)^-1 = invmod(g^w4)
        // for an explanation see: Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) page 9
        let mut t4_2 = g.modpow(&w4, p);
        t4_2 = t4_2.invmod(p).ok_or_else(|| Error::InvModError)?;

        for i in 0..size {
            let a_i = &shuffled_encryptions[i].a;
            let b_i = &shuffled_encryptions[i].b;
            let w_tilde_i = &w_tilde[i];

            t4_1 *= a_i.modpow(w_tilde_i, p);
            t4_2 *= b_i.modpow(w_tilde_i, p);
        }
        t4_1 %= p;
        t4_2 %= p;

        Ok((
            t1,
            t2,
            t3,
            (t4_1, t4_2),
            t_hat,
            w1,
            w2,
            w3,
            w4,
            w_hat,
            w_tilde,
        ))
    }

    pub fn permute_vector(input: Vec<BigUint>, permutation: &[usize]) -> Vec<BigUint> {
        let mut temp_ = Vec::new();

        // permute the input vector
        // same order as permutation vector
        for i in 0..input.len() {
            let j_i = permutation[i];
            let u_j_i = input[j_i].clone();
            temp_.push(u_j_i);
        }

        // ensure that both arrays have the same length
        // i.e. nothing went wrong
        assert_eq!(input.len(), temp_.len());
        temp_
    }
}
