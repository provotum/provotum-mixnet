use crate::{Error, Module, Trait};
use crypto::{
    helper::Helper,
    proofs::ShuffleProof,
    types::{Cipher, PermutationCommitment, PublicKey},
};
use num_bigint::BigUint;
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

        let size = encryptions.len();
        let params = &pk.params;
        let q = &pk.params.q();

        // get {size} independent generators: h
        let generators = Helper::get_generators(id, q, size);

        // commit to the given permutation: (c, r)
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;
        let permutation_commitment = ShuffleProof::generate_permutation_commitment(
            params,
            permutation,
            randoms,
            generators,
        );
        let commitments = permutation_commitment.commitments;

        // get {size} challenges: u = get_challenges(size, hash(e,e',c,pk))
        let mut challenges = ShuffleProof::get_challenges(
            size,
            encryptions,
            shuffled_encryptions,
            commitments,
            pk,
        );
        let mut temp_ = Vec::new();

        // permute the challenges -> same order as randoms + permuation
        for i in 0..challenges.len() {
            let j_i = permutation[i];
            let u_j_i = challenges[j_i].clone();
            temp_.push(u_j_i);
        }
        assert_eq!(challenges.len(), temp_.len());

        // reassign the permuted challenges
        challenges = temp_;

        // generate commitment chain: (c', r')
        let randoms: Vec<BigUint> = Self::get_random_biguints_less_than(q, size)?;
        let commitment_chain =
            ShuffleProof::generate_commitment_chain(challenges, randoms, params);
        Ok(())
    }
}
