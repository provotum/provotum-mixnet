use crate::types::{BigT, BigY, ElGamalParams, ModuloOperations};
use crate::{
    helper::Helper,
    types::{Cipher, PermutationCommitment, PublicKey},
};
use alloc::{vec, vec::Vec};
use num_bigint::BigUint;
use num_traits::{One, Zero};

pub struct ShuffleProof;

impl ShuffleProof {
    /// Generates a commitment to a permutation by committing to the columns of the corresponding permutation matrix.
    ///
    /// Inputs:
    /// - params ElGamalParams
    /// - permutation \[usize\]
    /// - randoms Vec<BigUint>, BigUint ∈ G_q
    /// - (independent) generators Vec<BigUint>, BigUint ∈ (G_q \ {1})
    pub fn generate_permutation_commitment(
        params: &ElGamalParams,
        permutation: &[usize],
        randoms: Vec<BigUint>,
        generators: Vec<BigUint>,
    ) -> PermutationCommitment {
        assert!(
            permutation.len() == randoms.len(),
            "permutation and randoms need to have the same length!"
        );
        assert!(
            permutation.len() == generators.len(),
            "permutation and generators need to have the same length!"
        );
        assert!(!permutation.is_empty(), "vectors cannot be empty!");

        let p = &params.p;
        let g = &params.g;
        let one = BigUint::one();
        let too_large = p.clone() + one;

        // initialize a vector of length: random.len() and default value p+1
        let mut commitments: Vec<BigUint> = vec![too_large.clone(); randoms.len()];
        assert!(commitments.len() == randoms.len());

        for i in 0..permutation.len() {
            // get the random value r at position j_i
            let j_i = permutation[i];
            let r_j_i = &randoms[j_i];

            // a random independent generator ∈ G_q
            let h_i = &generators[i];

            // create commitment
            // g_pow_r_j_i = g^(r_j_i) mod p
            let g_pow_r_j_i = g.modpow(r_j_i, p);

            // c_j_i = (g^(r_j_i) * h_i) mod p
            let c_j_i = g_pow_r_j_i.modmul(h_i, p);

            // insert c_j_i at position j_i in commitments vector
            let removed = commitments.remove(j_i);
            assert_eq!(removed, too_large);
            commitments.insert(j_i, c_j_i);
        }
        // make sure that none of the commitments are still a p+1 value
        // which is technically not possible since all chosen values are mod p
        // only if a value has not been replaced it can still be p+1
        assert!(commitments.iter().all(|value| value != &too_large));
        assert!(commitments.len() == randoms.len());
        PermutationCommitment {
            commitments,
            randoms,
        }
    }

    /// Generates a commitment chain c_1 -> c_N relative to a vector of
    /// public permuted challenges u' and the second public generator h ∈ G_q.
    ///
    /// Inputs:
    /// - challenges u': permuted public challenges u
    /// - randoms: new random values used for the commitment chain
    pub fn generate_commitment_chain(
        challenges: Vec<BigUint>,
        randoms: Vec<BigUint>,
        params: &ElGamalParams,
    ) -> PermutationCommitment {
        assert!(
            challenges.len() == randoms.len(),
            "challenges and randoms need to have the same length!"
        );
        assert!(!challenges.is_empty(), "vectors cannot be empty!");

        let p = &params.p;
        let q = &params.q();
        let g = &params.g;
        let h = &params.h;

        let mut commitment_values = Vec::new();
        let mut commitment_randoms = Vec::new();

        // initialize the commitment and random values with
        // R_0 = 0, U_0 = 1
        let mut r_i = BigUint::zero();
        let mut u_i = BigUint::one();
        let mut c_i: BigUint;

        for i in 0..challenges.len() {
            // retrieve and store the commitment random
            let random_i = randoms[i].clone();
            commitment_randoms.push(random_i.clone());

            // retrieve the challenge at index i
            let challenge_i = challenges[i].clone();

            // compute the commitment random: R_i = random_i + challenge_i * R_(i-1) mod q
            r_i = random_i + challenge_i.clone() * r_i.clone();
            r_i %= q;

            // compute U_i = challenge_i * U_(i-1) mod q
            u_i = challenge_i * u_i.clone();
            u_i %= q;

            // compute the commitment value: c_i = g^r_i * h^u_i mod p
            // g is the first and h the second public generator: g ∈ G_q, h ∈ G_q
            let g_pow_r_i = g.modpow(&r_i, p);
            let h_pow_u_i = h.modpow(&u_i, p);
            c_i = g_pow_r_i * h_pow_u_i;
            c_i %= p;
            commitment_values.push(c_i);
        }
        assert!(commitment_values.len() == commitment_randoms.len());
        PermutationCommitment {
            commitments: commitment_values,
            randoms: commitment_randoms,
        }
    }

    /// Algorithm 8.5: Computes n challenges 0 <= c_i <= 2^tau for a given of public value (vec_e, vec_e_tilde, vec_c).
    ///
    /// Inputs:
    /// - n: usize
    /// - vec_e: Vec<Cipher> "Encryptions"
    /// - vec_e_tilde: Vec<Cipher> "Shuffled Encryptions"
    /// - vec_c: Vec<BigUint> "Permutation Commitments"
    /// - pk: PublicKey
    pub fn get_challenges(
        n: usize,
        vec_e: Vec<Cipher>,
        vec_e_tilde: Vec<Cipher>,
        vec_c: Vec<BigUint>,
        pk: &PublicKey,
    ) -> Vec<BigUint> {
        assert!(n > 0, "at least one challenge must be generated!");
        assert!(
            vec_e.len() == vec_e_tilde.len(),
            "encryptions and shuffled_encryptions need to have the same length!"
        );
        assert!(
            vec_e.len() == vec_c.len(),
            "encryptions and permutation_commitments need to have the same length!"
        );
        assert!(!vec_e.is_empty(), "vectors cannot be empty!");
        let q = &pk.params.q();
        let mut challenges: Vec<BigUint> = Vec::new();

        // hash all inputs into a single BigUint
        let h = Helper::hash_challenges_inputs(vec_e, vec_e_tilde, vec_c, pk);

        for i in 0..n {
            let i_ = Helper::hash_vec_usize_to_biguint(&[i].to_vec());
            let mut c_i = Helper::hash_vec_biguints_to_biguint([h.clone(), i_].to_vec());

            // hash(h,i_) mod 2^T
            // Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) uses c_i ∈ Z_q
            // therefore, we use mod q
            // TODO: verify that this is correct!
            c_i %= q;
            challenges.push(c_i);
        }
        challenges
    }

    /// Algorithm 8.4: Computes a NIZKP challenge 0 <= c_i <= 2^tau for a given public value y and a public commitment t.
    ///
    /// Inputs:
    /// - public value: ((encryptions, shuffled_encryptions, permutation_commitments, chain_commitments, public_key)
    /// - public commitment: (t1, t2, t3, (t4_1, t4_2), (t_hat_0, ..., t_hat_(size-1)))
    pub fn get_challenge(public_value: BigY, public_commitment: BigT, q: &BigUint) -> BigUint {
        let value = Helper::hash_challenge_inputs(public_value, public_commitment);
        value % q
    }
}

#[cfg(test)]
mod tests {
    use super::ShuffleProof;
    use crate::{helper::Helper, random::Random, types::Cipher};
    use alloc::{vec, vec::Vec};
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    #[test]
    #[should_panic(expected = "permutation and randoms need to have the same length!")]
    fn it_should_panic_generate_permutation_commitment_different_size_permutations_randoms() {
        let (params, _, _) = Helper::setup_md_system();
        let p = &params.p;
        let vote_id = "2020-12-12_01".as_bytes();

        let randoms: [BigUint; 0] = [];
        let permutation = [1usize];
        let generators = Helper::get_generators(&vote_id, p, 1usize);

        ShuffleProof::generate_permutation_commitment(
            &params,
            &permutation,
            randoms.to_vec(),
            generators,
        );
    }

    #[test]
    #[should_panic(expected = "permutation and generators need to have the same length!")]
    fn it_should_panic_generate_permutation_commitment_different_size_permutations_generators() {
        let (params, _, _) = Helper::setup_md_system();

        let randoms = [BigUint::one()];
        let permutation = [1usize];
        let generators = Vec::new();

        ShuffleProof::generate_permutation_commitment(
            &params,
            &permutation,
            randoms.to_vec(),
            generators,
        );
    }

    #[test]
    #[should_panic(expected = "vectors cannot be empty!")]
    fn it_should_panic_generate_permutation_commitment_empty_inputs() {
        let (params, _, _) = Helper::setup_md_system();

        let randoms = [];
        let permutation = [];
        let generators = Vec::new();

        ShuffleProof::generate_permutation_commitment(
            &params,
            &permutation,
            randoms.to_vec(),
            generators,
        );
    }

    #[test]
    fn it_should_generate_permutation_commitment() {
        let (params, _, _) = Helper::setup_md_system();
        let p = &params.p;
        let q = params.q();
        let vote_id = "2020-12-12_01".as_bytes();

        // create a list of permutation
        let size = 3usize;
        let permutation = Random::generate_permutation(&size);

        // create three random values < q
        let randoms = [
            Random::get_random_less_than(&q),
            Random::get_random_less_than(&q),
            Random::get_random_less_than(&q),
        ];

        // get random generators ∈ G_q
        let generators = Helper::get_generators(&vote_id, p, size);

        // generate commitment
        let permutation_commitment = ShuffleProof::generate_permutation_commitment(
            &params,
            &permutation,
            randoms.to_vec(),
            generators,
        );

        // check that all commitments are: commitment < p
        assert!(permutation_commitment
            .commitments
            .iter()
            .all(|c| c < &params.p));
        // check that both have same number of elements: |commitments| == |randoms|
        assert_eq!(
            permutation_commitment.commitments.len(),
            permutation_commitment.randoms.len()
        );
    }

    #[test]
    #[should_panic(expected = "at least one challenge must be generated!")]
    fn it_should_panic_get_challenges_zero_challenges() {
        // SETUP
        let (_, _, pk) = Helper::setup_md_system();

        // fake values
        let size = 0usize;
        let encryptions = Vec::new();
        let shuffled_encryptions = Vec::new();
        let commitments = Vec::new();

        // TEST
        ShuffleProof::get_challenges(size, encryptions, shuffled_encryptions, commitments, &pk);
    }

    #[test]
    #[should_panic(expected = "encryptions and shuffled_encryptions need to have the same length!")]
    fn it_should_panic_get_challenges_different_sizes_encryptions_shuffled_encryptions() {
        // SETUP
        let (_, _, pk) = Helper::setup_md_system();

        // fake values
        let size = 1usize;
        let encryptions = vec![Cipher {
            a: BigUint::one(),
            b: BigUint::one(),
        }];
        let shuffled_encryptions = Vec::new();
        let commitments = Vec::new();

        // TEST
        ShuffleProof::get_challenges(size, encryptions, shuffled_encryptions, commitments, &pk);
    }

    #[test]
    #[should_panic(
        expected = "encryptions and permutation_commitments need to have the same length!"
    )]
    fn it_should_panic_get_challenges_different_sizes_encryptions_randoms() {
        // SETUP
        let (_, _, pk) = Helper::setup_md_system();

        // fake values
        let size = 1usize;
        let encryptions = vec![Cipher {
            a: BigUint::one(),
            b: BigUint::one(),
        }];
        let shuffled_encryptions = vec![Cipher {
            a: BigUint::zero(),
            b: BigUint::zero(),
        }];
        let commitments = Vec::new();

        // TEST
        ShuffleProof::get_challenges(size, encryptions, shuffled_encryptions, commitments, &pk);
    }

    #[test]
    #[should_panic(expected = "vectors cannot be empty!")]
    fn it_should_panic_get_challenges_empty_inputs() {
        // SETUP
        let (_, _, pk) = Helper::setup_md_system();

        // fake values
        let size = 1usize;
        let encryptions = Vec::new();
        let shuffled_encryptions = Vec::new();
        let re_encryption_randoms = Vec::new();

        // TEST
        ShuffleProof::get_challenges(
            size,
            encryptions,
            shuffled_encryptions,
            re_encryption_randoms,
            &pk,
        );
    }

    #[test]
    fn it_should_get_challenges() {
        // SETUP
        let (_, _, pk) = Helper::setup_md_system();

        let vote_id = "2020-12-12_01".as_bytes();
        let size = 3usize;
        let q = &pk.params.q();
        let p = &pk.params.p;
        let params = &pk.params;

        // generates a shuffle of three random encryptions of values: zero, one, two
        let encryptions = Random::generate_random_encryptions(&pk, &pk.params.q()).to_vec();
        let shuffle = Random::generate_shuffle(&pk, &pk.params.q(), encryptions.clone());

        // get the shuffled_encryptions & permutation from the shuffle
        let shuffled_encryptions = shuffle
            .iter()
            .map(|item| item.0.clone())
            .collect::<Vec<Cipher>>();
        assert!(shuffled_encryptions.len() == size);
        let permutation = shuffle.iter().map(|item| item.2).collect::<Vec<usize>>();
        assert!(permutation.len() == size);

        // generate {size} random values
        let mut randoms: Vec<BigUint> = Vec::new();
        for _ in 0..size {
            randoms.push(Random::get_random_less_than(q));
        }

        // get {size} independent generators
        let generators = Helper::get_generators(&vote_id, p, size);

        // get the permutation commitents
        let permutation_commitment = ShuffleProof::generate_permutation_commitment(
            params,
            &permutation,
            randoms,
            generators,
        );
        let commitments = permutation_commitment.commitments;

        // TEST: challenge value generation
        let challenges =
            ShuffleProof::get_challenges(size, encryptions, shuffled_encryptions, commitments, &pk);

        // check that:
        // 1. three challenges are generated
        // 2. all challenge values are < q
        assert_eq!(challenges.len(), 3);
        assert!(challenges.iter().all(|value| value < &pk.params.q()));
    }

    #[test]
    #[should_panic(expected = "challenges and randoms need to have the same length!")]
    fn it_should_panic_generate_commitment_chain_different_size_challenges_randoms() {
        // SETUP
        let (params, _, _) = Helper::setup_md_system();

        // fake values
        let challenges = vec![BigUint::one()];
        let randoms: Vec<BigUint> = Vec::new();

        // TEST
        ShuffleProof::generate_commitment_chain(challenges, randoms, &params);
    }

    #[test]
    #[should_panic(expected = "vectors cannot be empty!")]
    fn it_should_panic_generate_commitment_chain_empty_inputs() {
        // SETUP
        let (params, _, _) = Helper::setup_md_system();

        // fake values
        let challenges: Vec<BigUint> = Vec::new();
        let randoms: Vec<BigUint> = Vec::new();

        // TEST
        ShuffleProof::generate_commitment_chain(challenges, randoms, &params);
    }

    #[test]
    fn it_should_panic_generate_commitment_chain() {
        // SETUP
        let (params, _, _) = Helper::setup_md_system();

        let size = 3usize;
        let p = &params.p;
        let q = &params.q();

        // fake challenge values
        let mut challenges: Vec<BigUint> = Vec::new();
        for _ in 0..size {
            challenges.push(Random::get_random_less_than(q));
        }

        // generate {size} random values
        let mut randoms: Vec<BigUint> = Vec::new();
        for _ in 0..size {
            randoms.push(Random::get_random_less_than(q));
        }

        // TEST
        let commitent_chain = ShuffleProof::generate_commitment_chain(challenges, randoms, &params);

        // check that:
        // 1. all commitment values are < q
        // 2. there exist the same number of commitments + randoms
        assert!(commitent_chain.commitments.iter().all(|value| value < p));
        assert!(commitent_chain.randoms.iter().all(|value| value < q));
        assert_eq!(
            commitent_chain.commitments.len(),
            commitent_chain.randoms.len()
        );
    }
}
