use crate::types::PermutationCommitment;
use crate::types::{ElGamalParams, ModuloOperations};
use alloc::{vec, vec::Vec};
use num_bigint::BigUint;
use num_traits::One;

pub struct ShuffleProof;

impl ShuffleProof {
    /// The offline part of the shuffle proof
    /// i.e. generate the permutation matrix commitment
    pub fn offline() {
        unimplemented!()
    }

    /// Generates a commitment to a permutation by committing to the columns of the corresponding permutation matrix.
    ///
    /// Inputs:
    /// - params ElGamalParams
    /// - permutations \[usize\]
    /// - randoms Vec<BigUint>, BigUint ∈ G_q
    /// - (independent) generators Vec<BigUint>, BigUint ∈ (G_q \ {1})
    fn generate_permutation_commitment(
        params: &ElGamalParams,
        permutations: &[usize],
        randoms: Vec<BigUint>,
        generators: Vec<BigUint>,
    ) -> PermutationCommitment {
        assert!(
            permutations.len() == randoms.len(),
            "permutations and randoms need to have the same length!"
        );
        assert!(
            permutations.len() == generators.len(),
            "permutations and generators need to have the same length!"
        );
        assert!(!permutations.is_empty(), "vectors cannot be empty!");

        let p = &params.p;
        let g = &params.g;
        let one = BigUint::one();
        let too_large = p.clone() + one;

        // initialize a vector of length: random.len() and default value p+1
        let mut commitments: Vec<BigUint> = vec![too_large.clone(); randoms.len()];
        assert!(commitments.len() == randoms.len());

        for i in 0..permutations.len() {
            // get the random value r at position j_i
            let j_i = permutations[i];
            let r_j_i = &randoms[j_i];

            // a random independent generator ∈ G_q
            let h = &generators[i];

            // create commitment
            // g_pow_r_j_i = g^(r_j_i) mod p
            let g_pow_r_j_i = g.modpow(r_j_i, p);

            // c_j_i = (g^(r_j_i) * h_i) mod p
            let c_j_i = g_pow_r_j_i.modmul(h, p);

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

    /// The online part of the shuffle proof
    ///
    pub fn online() {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use core::ops::Add;

    use super::ShuffleProof;
    use crate::{helper::Helper, random::Random, types::Cipher};
    use alloc::{vec, vec::Vec};
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    #[should_panic(expected = "permutations and randoms need to have the same length!")]
    fn it_should_panic_generate_permutation_commitment_different_size_permutations_randoms() {
        let (params, _, pk) = Helper::setup_system(
            b"170141183460469231731687303715884105727",
            b"2",
            b"1701411834604692317316",
        );
        let q = pk.params.q();
        let vote_id = 123usize;

        let randoms: [BigUint; 0] = [];
        let permutations = [1usize];
        let generators = Helper::get_generators(vote_id, &q, 1usize);

        ShuffleProof::generate_permutation_commitment(
            &params,
            &permutations,
            randoms.to_vec(),
            generators,
        );
    }

    #[test]
    #[should_panic(expected = "permutations and generators need to have the same length!")]
    fn it_should_panic_generate_permutation_commitment_different_size_permutations_generators() {
        let (params, _, pk) = Helper::setup_system(
            b"170141183460469231731687303715884105727",
            b"2",
            b"1701411834604692317316",
        );
        let q = pk.params.q();
        let vote_id = 123usize;

        let randoms = [BigUint::one()];
        let permutations = [1usize];
        let generators = Vec::new();

        ShuffleProof::generate_permutation_commitment(
            &params,
            &permutations,
            randoms.to_vec(),
            generators,
        );
    }

    #[test]
    #[should_panic(expected = "vectors cannot be empty!")]
    fn it_should_panic_generate_permutation_commitment_empty_inputs() {
        let (params, _, pk) = Helper::setup_system(
            b"170141183460469231731687303715884105727",
            b"2",
            b"1701411834604692317316",
        );
        let q = pk.params.q();
        let vote_id = 123usize;

        let randoms = [];
        let permutations = [];
        let generators = Vec::new();

        ShuffleProof::generate_permutation_commitment(
            &params,
            &permutations,
            randoms.to_vec(),
            generators,
        );
    }

    #[test]
    fn it_should_generate_permutation_commitment() {
        let (params, _, pk) = Helper::setup_system(
            b"170141183460469231731687303715884105727",
            b"2",
            b"1701411834604692317316",
        );
        let q = pk.params.q();
        let vote_id = 123usize;

        // create a list of permutations
        let size = 3usize;
        let permutations = Random::generate_permutation(&size);

        // create three random values < q
        let randoms = [
            Random::get_random_less_than(&q),
            Random::get_random_less_than(&q),
            Random::get_random_less_than(&q),
        ];

        // get random generators ∈ G_q
        let generators = Helper::get_generators(vote_id, &q, size);

        // generate commitment
        let permutation_commitment = ShuffleProof::generate_permutation_commitment(
            &params,
            &permutations,
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
}
