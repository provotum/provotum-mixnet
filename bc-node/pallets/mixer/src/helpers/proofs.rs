use crate::{Error, Module, Trait};
use crypto::{
    helper::Helper,
    proofs::ShuffleProof,
    types::ElGamalParams,
    types::{Cipher, ModuloOperations, PublicKey},
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sp_std::{if_std, vec, vec::Vec};

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
        let generators = Helper::get_generators(id, q, size);

        // commit to the given permutation: (vec_c, vec_r)
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;
        let permutation_commitment = ShuffleProof::generate_permutation_commitment(
            params,
            permutation,
            randoms,
            generators.clone(),
        );
        let vec_c = permutation_commitment.commitments;
        let vec_r = permutation_commitment.randoms;

        // get {size} challenges
        // vec_u = get_challenges(size, hash(e, e_tilde, vec_c, pk))
        let vec_u = ShuffleProof::get_challenges(
            size,
            e.clone(),
            e_tilde.clone(),
            vec_c.clone(),
            pk,
        );
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
                generators,
                e_tilde.clone(),
                pk,
                size,
            )?;

        if_std! {
            // println!("prover - vec_t_hat: {:?}\n", vec_t_hat);
        }

        // generate challenge from (y, t)
        // public value y = ((e, e_tilde, vec_c, vec_c_hat, pk)
        // public commitment t = (t1, t2, t3, (t4_1, t4_2), (t_hat_0, ..., t_hat_(size-1)))
        let public_value = (e, e_tilde, vec_c.clone(), vec_c_hat.clone(), pk);
        if_std! {
            println!("prover - t1: {:?},\n t2: {:?},\n t3: {:?},\n t4_1: {:?},\n t4_2: {:?}\n", t1,t2, t3, t4_1, t4_2);
        }
        let public_commitment = (t1, t2, t3, (t4_1, t4_2), vec_t_hat);
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
        if_std! {
            // println!("prover - s1: {:?}, s2: {:?}, s3: {:?}, s4: {:?}", s1, s2, s3, s4);
            // println!("prover - vec_s_tilde: {:?}", vec_s_tilde);
        }
        let s = (s1, s2, s3, s4, vec_s_hat, vec_s_tilde);

        // return (challenge, s, permutation_commitments, chain_commitments)
        Ok((challenge, s, vec_c, vec_c_hat))
    }

    pub fn verify_shuffle_proof(
        id: usize, // election id
        proof: (
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
        encryptions: Vec<Cipher>,
        shuffled_encryptions: Vec<Cipher>,
        pk: &PublicKey,
    ) -> Result<bool, Error<T>> {
        let e = encryptions;
        let e_tilde = shuffled_encryptions;
        let (challenge, s, vec_c, vec_c_hat) = proof;
        let (s1, s2, s3, s4, vec_s_hat, vec_s_tilde) = s;

        // input checks
        assert!(
            e.len() == e_tilde.len(),
            "encryptions and shuffled_encryptions need to have the same length!"
        );
        assert!(
            e.len() == vec_c.len(),
            "encryptions and permutation_commitments need to have the same length!"
        );
        assert!(
            e.len() == vec_c_hat.len(),
            "encryptions and permutation_chain_commitments need to have the same length!"
        );
        assert!(
            e.len() == vec_s_hat.len(),
            "encryptions and vec_s_hat need to have the same length!"
        );
        assert!(
            e.len() == vec_s_tilde.len(),
            "encryptions and vec_s_hat need to have the same length!"
        );
        assert!(!e.is_empty(), "vectors cannot be empty!");

        // the size of the shuffle (# of encrypted votes)
        let size = e.len();
        let params = &pk.params;
        let h = &params.h;
        let p = &params.p;
        let q = &params.q();

        // get {size} independent generators: vec_h
        let vec_h = Helper::get_generators(id, q, size);

        // get {size} challenges
        // vec_u = get_challenges(size, hash(e, e_tilde, vec_c, pk))
        let vec_u = ShuffleProof::get_challenges(
            size,
            e.clone(),
            e_tilde.clone(),
            vec_c.clone(),
            pk,
        );

        // get c_hat_0
        // h = the 2. public generator
        let c_hat_0 = h;

        // get c_flat = Π(c_i) / Π(vec_h_i) mod p
        // vec_c = permutation_commitments
        // vec_h = public generators
        let product_vec_c = vec_c
            .iter()
            .fold(BigUint::one(), |prod, c| prod.modmul(c, p));
        let product_generators = vec_h
            .iter()
            .fold(BigUint::one(), |prod, gen| prod.modmul(gen, p));
        let c_flat = product_vec_c
            .moddiv(&product_generators, p)
            .ok_or_else(|| Error::DivModError)?;

        // get u = Π(vec_u_i) mod q
        // vec_u = challenges
        let u = vec_u
            .iter()
            .fold(BigUint::one(), |product, u| product.modmul(u, q));

        // get value c_hat = c_hat_n / h^u mod p
        // vec_c_hat = permutation_chain_commitments
        let h_pow_u = h.modpow(&u, p);
        let c_hat_n = &vec_c_hat[size - 1];
        let c_hat = c_hat_n
            .moddiv(&h_pow_u, p)
            .ok_or_else(|| Error::DivModError)?;
        if_std! {
            println!("verifier c_hat: {:?}\n", c_hat);
        }

        // get value c_tilde = Π(c_i^u_i) mod p
        // vec_c = permutation_commitments
        // vec_u = challenges
        let c_tilde = Self::zip_vectors_multiply_a_pow_b(&vec_c, &vec_u, p);

        // vec_a = vector of all components a (encryption { a, b })
        // vec_b = vector of all components b (encryption { a, b })
        let vec_a = e.clone().into_iter().map(|v| v.a).collect();
        let vec_b = e.clone().into_iter().map(|v| v.b).collect();
        let a_tilde = Self::zip_vectors_multiply_a_pow_b(&vec_a, &vec_u, p);
        let b_tilde = Self::zip_vectors_multiply_a_pow_b(&vec_b, &vec_u, p);

        // generate vec_t_hat values
        let vec_t_hat = Self::get_vec_t_hat_verifier(
            &c_hat_0,
            &challenge,
            &vec_c_hat,
            &vec_s_hat,
            &vec_s_tilde,
            size,
            params,
        );
        if_std! {
            // println!("verifier - vec_t_hat: {:?}\n", vec_t_hat);
        }

        let (t1, t2, t3, (t4_1, t4_2)) = Self::get_t_values_verifier(
            &c_flat,
            &c_hat,
            &c_tilde,
            &challenge,
            &a_tilde,
            &b_tilde,
            &e_tilde,
            &vec_h,
            &vec_s_tilde,
            &s1,
            &s2,
            &s3,
            &s4,
            size,
            pk,
        )?;

        // generate challenge from (y, t)
        // public value y = ((e, e_tilde, vec_c, vec_c_hat, pk)
        // public commitment t = (t1, t2, t3, (t4_1, t4_2), (t_hat_0, ..., t_hat_(size-1)))
        let public_value = (e, e_tilde, vec_c, vec_c_hat, pk);
        if_std! {
            println!("verifier - t1: {:?},\n t2: {:?},\n t3: {:?},\n t4_1: {:?},\n t4_2: {:?}\n", t1, t2, t3, t4_1, t4_2 );
        }
        let public_commitment = (t1, t2, t3, (t4_1, t4_2), vec_t_hat);
        let recomputed_challenge =
            ShuffleProof::get_challenge(public_value, public_commitment);

        let is_proof_valid = recomputed_challenge == challenge;
        if_std! {
            println!("is_proof_valid: {:?}", is_proof_valid)
        }
        Ok(is_proof_valid)
    }

    fn get_t_values_verifier(
        c_flat: &BigUint,
        c_hat: &BigUint,
        c_tilde: &BigUint,
        challenge: &BigUint,
        a_tilde: &BigUint,
        b_tilde: &BigUint,
        e_tilde: &Vec<Cipher>,
        vec_h: &Vec<BigUint>,
        vec_s_tilde: &Vec<BigUint>,
        s1: &BigUint,
        s2: &BigUint,
        s3: &BigUint,
        s4: &BigUint,
        size: usize,
        public_key: &PublicKey,
    ) -> Result<(BigUint, BigUint, BigUint, (BigUint, BigUint)), Error<T>> {
        let g = &public_key.params.g;
        let p = &public_key.params.p;
        let pk = &public_key.h;

        if_std! {
            // println!("verifier - s1: {:?}, s2: {:?}, s3: {:?}, s4: {:?}", s1, s2, s3, s4);
            // println!("verifier - vec_s_tilde: {:?}", vec_s_tilde);
        }

        // get t1 = c_flat^challenge * g^s1 mod p
        let t1 = c_flat.modpow(challenge, p).modmul(&g.modpow(s1, p), p);

        // get t2 = c_hat^challenge * g^s2 mod p
        let g_pow_s2 = g.modpow(s2, p);
        let c_hat_pow_challenge = c_hat.modpow(challenge, p);
        let t2 = c_hat_pow_challenge.modmul(&g_pow_s2, p);
        if_std! {
            println!("verifier - \ng^s2: {:?},\n c_hat^challenge: {:?},\n t2: {:?}", g_pow_s2, c_hat_pow_challenge, t2);
            // println!("verifier - vec_s_tilde: {:?}", vec_s_tilde);
        }

        // get t3 = c_tilde^challenge * g^s3 * Π(h_i^s_tilde_i) mod p
        let prod_h_s_tilde = Self::zip_vectors_multiply_a_pow_b(&vec_h, &vec_s_tilde, p);
        let mut t3 = c_tilde.modpow(challenge, p);
        t3 = t3.modmul(&g.modpow(s3, p), p);
        t3 = t3.modmul(&prod_h_s_tilde, p);

        // get t4_1 =
        // a_tilde^challenge * pk^-s4 * Π(vec_a_tilde_i^s_tilde_i) mod p

        // pk^-s4 = (pk^-1)^s4 = (pk^s4)^-1 = invmod(pk^s4)
        // for an explanation see: Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) page 9
        let mut pk_pow_minus_s4 = pk.modpow(s4, p);
        pk_pow_minus_s4 = pk_pow_minus_s4
            .invmod(p)
            .ok_or_else(|| Error::InvModError)?;

        // compute prod_a = Π(vec_a_tilde_i^s_tilde_i)
        // compute prod_b = Π(vec_b_tilde_i^s_tilde_i)
        let mut prod_a = BigUint::one();
        let mut prod_b = BigUint::one();

        for i in 0..size {
            // a_tilde_i = component a of entry i in shuffled_encryptions
            let a_tilde_i = &e_tilde[i].a;
            // b_tilde_i = component b of entry i in shuffled_encryptions
            let b_tilde_i = &e_tilde[i].b;
            let s_tilde_i = &vec_s_tilde[i];

            let a_tilde_i_pow_s_tilde_i = a_tilde_i.modpow(s_tilde_i, p);
            prod_a = prod_a.modmul(&a_tilde_i_pow_s_tilde_i, p);

            let b_tilde_i_pow_s_tilde_i = b_tilde_i.modpow(s_tilde_i, p);
            prod_b = prod_b.modmul(&b_tilde_i_pow_s_tilde_i, p);
        }

        // compute t4_1
        let mut t4_1 = a_tilde.modpow(&challenge, p);
        t4_1 = t4_1.modmul(&pk_pow_minus_s4, p);
        t4_1 = t4_1.modmul(&prod_a, p);

        // get t4_2 =
        // b_tilde^challenge * g^-s4 * Π(vec_b_tilde_i^s_tilde_i) mod p

        // g^-s4 = (g^-1)^s4 = (g^s4)^-1 = invmod(g^s4)
        // for an explanation see: Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) page 9
        let mut g_pow_minus_s4 = g.modpow(&s4, p);
        g_pow_minus_s4 = g_pow_minus_s4.invmod(p).ok_or_else(|| Error::InvModError)?;

        // compute t4_2
        let mut t4_2 = b_tilde.modpow(challenge, p);
        t4_2 = t4_2.modmul(&g_pow_minus_s4, p);
        t4_2 = t4_2.modmul(&prod_b, p);

        Ok((t1, t2, t3, (t4_1, t4_2)))
    }

    fn get_vec_t_hat_verifier(
        c_hat_0: &BigUint,
        challenge: &BigUint,
        vec_c_hat: &Vec<BigUint>,
        vec_s_hat: &Vec<BigUint>,
        vec_s_tilde: &Vec<BigUint>,
        size: usize,
        params: &ElGamalParams,
    ) -> Vec<BigUint> {
        let g = &params.g;
        let p = &params.p;

        // create an extended vec_c_hat
        // extended = [c_hat_0, ...c_hat];
        let mut vec_c_hat_extended = vec![c_hat_0];
        vec_c_hat_extended.extend(vec_c_hat);
        assert!(
            vec_c_hat_extended.len() == (size + 1usize),
            "vec_c_hat_extended needs to be 1 element larger than size!"
        );

        let mut vec_t_hat = Vec::new();
        for i in 0..size {
            // c_hat_i ^ challenge
            // i + 1 = the original i in vec_c_hat since the vector was extended above
            let c_hat_i = vec_c_hat_extended[i + 1];
            let c_hat_i_pow_challenge = c_hat_i.modpow(&challenge, p);

            // g ^ s_hat_i
            let s_hat_i = &vec_s_hat[i];
            let g_pow_s_hat_i = g.modpow(&s_hat_i, p);

            // c_hat_(i-1) ^ s_tilde_i
            let s_tilde_i = &vec_s_tilde[i];
            let c_hat_i_minus_1 = vec_c_hat_extended[i];
            let c_hat_i_minus_1_pow_s_tilde_i = c_hat_i_minus_1.modpow(&s_tilde_i, p);

            // compute t_hat_i =
            // c_hat_i ^ challenge * g ^ s_hat_i * c_hat_(i-1) ^ s_tilde_i % p
            let t_hat_i = c_hat_i_pow_challenge
                .modmul(&g_pow_s_hat_i, p)
                .modmul(&c_hat_i_minus_1_pow_s_tilde_i, p);
            vec_t_hat.push(t_hat_i);
        }
        assert!(
            vec_t_hat.len() == size,
            "vec_t_hat should have length: {size}",
        );
        vec_t_hat
    }

    /// zips vectors a and b.
    /// performs component-wise operation: x = a_i^b_i % modulus
    /// multiplies all component-wise operation results
    /// Π(x) % modulus
    fn zip_vectors_multiply_a_pow_b(
        a: &Vec<BigUint>,
        b: &Vec<BigUint>,
        modulus: &BigUint,
    ) -> BigUint {
        assert!(a.len() == b.len(), "vectors must have the same length!");
        let iterator = a.iter().zip(b.iter());
        let value = iterator.fold(BigUint::one(), |prod, (a_i, b_i)| {
            // Π(a_i^b_i % modulus) % modulus
            prod.modmul(&a_i.modpow(b_i, modulus), modulus)
        });
        value
    }

    /// zips vectors a and b.
    /// performs component-wise operation: x = a_i * b_i % modulus
    /// sums all component-wise operation results
    /// Σ(x) % modulus
    fn zip_vectors_sum_products(
        a: &Vec<BigUint>,
        b: &Vec<BigUint>,
        modulus: &BigUint,
    ) -> BigUint {
        assert!(a.len() == b.len(), "vectors must have the same length!");
        let iterator = a.iter().zip(b.iter());
        // Σ(a_i * b_i) % modulus
        let value = iterator.fold(BigUint::zero(), |sum, (a_i, b_i)| {
            sum.modadd(&a_i.modmul(b_i, modulus), modulus)
        });
        value
    }

    pub fn generate_s_values(
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
        let v_i = BigUint::one();
        v.push(v_i.clone());

        // v_(n-1) = 1
        // for i = N-2..0 do
        for i in (0..(size - 1)).rev() {
            //
            let u_tilde_i = &u_tilde[i + 1];

            // v_(i-1) = u_tilde_i * v_i mod q
            let v_i = u_tilde_i.modmul(&v_i, q);
            v.push(v_i.clone());
        }

        // TODO: check if this is necessary
        // reverse the order in v
        if_std! {
            println!("prover - v: {:?}\n", v)
        }
        v.reverse();
        if_std! {
            println!("prover - v.reverse(): {:?}\n", v)
        }

        // get r values
        // vec_r_hat -> random values of commitment chain
        // get r_hat = Σ(vec_r_hat_i * v_i) mod q
        let r_hat = Self::zip_vectors_sum_products(&vec_r_hat, &v, q);
        if_std! {
            println!("prover - r_hat: {:?},\n w2: {:?}\n", r_hat, w2)
        }

        // we add q to w2 to ensure the value will always be >0
        // s2 = w2 - challenge * r_hat % q
        let s2 = w2.modsub(&challenge.modmul(&r_hat, q), q);

        // vec_r -> random values of permutation commitment
        // get r = Σ(vec_r_i * u_i) mod q
        let r = Self::zip_vectors_sum_products(&vec_r, &vec_u, q);
        if_std! {
            println!("prover - r: {:?},\n w3: {:?}\n", r, w3)
        }

        // we add q to w3 to ensure the value will always be >0
        // s3 = w3 - challenge * r % q
        let s3 = w3.modsub(&challenge.modmul(&r, q), q);

        // vec_r_tilde -> random values of re-encryption
        // get r_tilde
        let r_tilde = Self::zip_vectors_sum_products(&vec_r_tilde, &vec_u, q);
        if_std! {
            println!("prover - r_tilde: {:?},\n w4: {:?}\n", r_tilde, w4)
        }

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
            let s_hat_i = ((q + w_hat_i) - challenge.modmul(r_hat_i, q)) % q;
            vec_s_hat.push(s_hat_i);

            let w_tilde_i = &vec_w_tilde[i];
            let u_tilde_i = &u_tilde[i];

            // s_tilde_i = w_tilde_i - challenge * u_tilde_i mod q
            // we add q to w_tilde_i to ensure the value will always be >0
            let s_tilde_i = ((q + w_tilde_i) - challenge.modmul(u_tilde_i, q)) % q;
            vec_s_tilde.push(s_tilde_i);
        }
        (s1, s2, s3, s4, vec_s_hat, vec_s_tilde)
    }

    pub fn generate_t_and_w_values(
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
        let mut vec_w_tilde: Vec<BigUint> = Vec::new();
        let mut vec_w_hat: Vec<BigUint> = Vec::new();
        let mut vec_t_hat: Vec<BigUint> = Vec::new();

        // part 1: generate vec_t_hat & vec_w_tilde values

        for i in 0..size {
            let w_hat_i = Self::get_random_biguint_less_than(q)?;
            let w_tilde_i = Self::get_random_biguint_less_than(q)?;
            vec_w_hat.push(w_hat_i.clone());
            vec_w_tilde.push(w_tilde_i.clone());

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
            let w_tilde_i = &vec_w_tilde[i];

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
            vec_t_hat,
            w1,
            w2,
            w3,
            w4,
            vec_w_hat,
            vec_w_tilde,
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
