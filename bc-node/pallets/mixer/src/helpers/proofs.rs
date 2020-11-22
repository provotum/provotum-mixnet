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
    /// Generates a shuffle proof relative to encryptions e and e', which
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
    ) -> Result<(), Error<T>> {
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
        let commitments = permutation_commitment.commitments;

        // get {size} challenges
        // u_tilde = get_challenges(size, hash(e,e',c,pk))
        let mut u_tilde = ShuffleProof::get_challenges(
            size,
            encryptions,
            shuffled_encryptions.clone(),
            commitments,
            pk,
        );
        // permute the challenges -> same order as randoms + permuation
        u_tilde = Self::permute_vector(u_tilde, permutation);

        // generate commitment chain: (c', r')
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;

        // (vector_c_hat, vector_r_hat) = GenCommitmentChain(vector_u_tilde)
        // vector_u_tilde = challenges, re-ordered according to the permutation
        let commitment_chain =
            ShuffleProof::generate_commitment_chain(u_tilde.clone(), randoms, params);
        let r_hat = commitment_chain.randoms;

        // generate t & w values
        let (t1, t2, t3, (t4_1, t4_2), t_hat) = Self::generate_t_and_w_values(
            r_hat,
            u_tilde.clone(),
            generators,
            shuffled_encryptions,
            pk,
            size,
        )?;

        // generate challenge from (y, t)
        // y = ((e, e', c, c', pk)
        // t = (t1, t2, t3, (t4_1, t4_2), (t_hat_0, ..., t_hat_(size-1)))

        // get r_flat
        // sum(r_i) mod q where r_i are the random values from the permutation commitment

        // get s1 = (w1 - c * r_flat) mod q

        // generate v values
        // start with value v_n = 1
        let mut v = Vec::new();
        let mut v_i = BigUint::one();
        v.push(v_i.clone());

        for i in (0..size).rev() {
            let u_tilde_i = &u_tilde[i];

            // v_(i-1) = u_tilde_i * v_i mod q
            let v_i = u_tilde_i.modmul(&v_i, q);
            v.push(v_i.clone());
        }

        // reverse the order in v
        v.reverse();

        // get r values
        // get r_hat

        // get r

        // get r_tilde

        // generate s_hat and s_tilde values

        // s = (s1, s2, s3, s4, (s_hat_0, ..., s_hat_(size-1)), (s_tilde_0, ..., s_tilde_(size-1)))
        // return (challenge, s, permutation_commitments, chain_commitments)
        Ok(())
    }

    pub fn generate_t_and_w_values(
        r_hat: Vec<BigUint>,
        u_tilde: Vec<BigUint>,
        generators: Vec<BigUint>,
        shuffled_encryptions: Vec<Cipher>,
        public_key: &PublicKey,
        size: usize,
    ) -> Result<(BigUint, BigUint, BigUint, (BigUint, BigUint), Vec<BigUint>), Error<T>>
    {
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
        let mut t_hat: Vec<BigUint> = Vec::new();

        // part 1: generate t_hat & w_tilde values

        for i in 0..size {
            let w_hat_i = Self::get_random_biguint_less_than(q)?;
            let w_tilde_i = Self::get_random_biguint_less_than(q)?;
            w_tilde.push(w_tilde_i.clone());

            // get random value r_hat_i used during commitment chain generation
            let r_hat_i = r_hat[i].clone();

            // get challenge value u_tilde_i
            let u_tilde_i = u_tilde[i].clone();

            // r_i_dash = w_hat_i + w_tilde_i * r_(i-1) mod q
            r_i_dash = (w_hat_i + w_tilde_i.clone() * r_i.clone()) % q;

            // r_i = r_hat_i + u_tilde_i * r_(i-1) mod q
            r_i = (r_hat_i + u_tilde_i.clone() * r_i) % q;

            // u_i_dash = w_tilde_i * u_(i-1) mod q
            u_i_dash = (w_tilde_i * u_i.clone()) % q;

            // u_i = u_tilde_i * u_(i-1) mod q
            u_i = (u_tilde_i * u_i) % q;

            // t_hat_i = g^r_i_dash * h_u_i_dash mod p
            t_hat_i = (g.modpow(&r_i_dash, p) * h.modpow(&u_i_dash, p)) % p;
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
        // TODO: not sure if mod p is correct
        let inv_w4 = w4.invmod(p).ok_or_else(|| Error::InvModError)?;
        // pk is the public key
        let mut t4_1 = pk.modpow(&inv_w4, p);
        // g is the first public generator
        let mut t4_2 = g.modpow(&inv_w4, p);

        for i in 0..size {
            let a_i = &shuffled_encryptions[i].a;
            let b_i = &shuffled_encryptions[i].b;
            let w_tilde_i = &w_tilde[i];

            t4_1 *= a_i.modpow(w_tilde_i, p);
            t4_2 *= b_i.modpow(w_tilde_i, p);
        }
        t4_1 %= p;
        t4_2 %= p;

        Ok((t1, t2, t3, (t4_1, t4_2), t_hat))
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
