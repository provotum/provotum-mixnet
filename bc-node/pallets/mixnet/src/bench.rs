#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::types::{PublicParameters, ShuffleProof as Proof, Wrapper};
use crypto::{
    encryption::ElGamal, helper::Helper, types::Cipher as BigCipher, types::PublicKey as ElGamalPK,
};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use hex_literal::hex;
use sp_std::vec;

use crate::Module as PalletMixnet;

fn setup_public_key<T: Trait>(pk: SubstratePK) -> Result<(), &'static str> {
    // create the submitter (i.e. the public key submitter)
    let account: T::AccountId = whitelisted_caller();
    let who = RawOrigin::Signed(account.into());

    // store created public key and public parameters
    let _setup_result = PalletMixnet::<T>::store_public_key(who.into(), pk)?;
    Ok(())
}

fn setup_vote<T: Trait>(params: PublicParameters) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // create the submitter (i.e. the voting_authority)
    // use Alice as VotingAuthority
    let account_id: [u8; 32] =
        hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d").into();
    let account = T::AccountId::decode(&mut &account_id[..]).unwrap();
    let who = RawOrigin::Signed(account.into());

    // create the vote
    let vote_id = "20201212".as_bytes().to_vec();
    let vote_title = "Popular Vote of 12.12.2020".as_bytes().to_vec();

    let topic_id = "20201212-01".as_bytes().to_vec();
    let topic_question = "Moritz for President?".as_bytes().to_vec();
    let topic: Topic = (topic_id.clone(), topic_question);
    let topics = vec![topic];

    PalletMixnet::<T>::create_vote(who.into(), vote_id.clone(), vote_title, params, topics)?;
    Ok((vote_id, topic_id))
}

fn setup_shuffle<T: Trait>(size: usize) -> Result<(Vec<u8>, Vec<u8>, ElGamalPK), &'static str> {
    // setup
    let (params, _, pk) = Helper::setup_lg_system();
    let (vote_id, topic_id) = setup_vote::<T>(params.into())?;
    setup_public_key::<T>(pk.clone().into())?;

    // create messages and random values
    let q = &pk.params.q();
    let messages = PalletMixnet::<T>::get_random_biguints_less_than(q, size)?;
    let randoms = PalletMixnet::<T>::get_random_biguints_less_than(q, size)?;

    // create the voter (i.e. the transaction signer)
    let account: T::AccountId = whitelisted_caller();
    let voter = RawOrigin::Signed(account.into());

    for index in 0..messages.len() {
        let random = &randoms[index];
        let message = &messages[index];

        // transform the ballot into a from that the blockchain can handle
        // i.e. a Substrate representation { a: Vec<u8>, b: Vec<u8> }
        let cipher: Cipher = ElGamal::encrypt(message, random, &pk).into();
        let answers: Vec<(TopicId, Cipher)> = vec![(topic_id.clone(), cipher)];
        let ballot: Ballot = Ballot { answers };
        PalletMixnet::<T>::cast_ballot(voter.clone().into(), vote_id.clone(), ballot)?;
    }
    Ok((topic_id, vote_id, pk))
}

fn setup_shuffle_proof<T: Trait>(
    size: usize,
) -> Result<
    (
        Vec<u8>,
        Vec<BigCipher>,
        Vec<BigCipher>,
        Vec<BigUint>,
        Vec<usize>,
        ElGamalPK,
    ),
    &'static str,
> {
    let (topic_id, vote_id, pk) = setup_shuffle::<T>(size)?;

    // get the encrypted votes
    let e: Vec<BigCipher> = Wrapper(PalletMixnet::<T>::ciphers(&topic_id)).into();
    ensure!(e.len() == size, "# of votes on chain is not correct");

    // shuffle the votes
    let result = PalletMixnet::<T>::shuffle_ciphers(&topic_id);
    let s: (Vec<BigCipher>, Vec<BigUint>, Vec<usize>) = result.unwrap();
    let e_hat = s.0; // the shuffled votes
    let r = s.1; // the re-encryption randoms
    let permutation = s.2;
    Ok((vote_id, e, e_hat, r, permutation, pk))
}

benchmarks! {
    _{ }

    store_public_key {
        let (_, _, pk) = Helper::setup_lg_system();

        // create the submitter (i.e. the public key submitter)
        let account: T::AccountId = whitelisted_caller();
        let who = RawOrigin::Signed(account.into());
    }: {
        // store created public key and public parameters
        let _result = PalletMixnet::<T>::store_public_key(who.into(), pk.clone().into());
    }
    verify {
        // fetch the public key from the chain
        let pk_from_chain: ElGamalPK = PalletMixnet::<T>::public_key().unwrap().into();
        ensure!(pk_from_chain == pk, "fail pk_from_chain != pk");
    }

    random_range {
        let lower: usize = 0;
        let upper: usize = 100;
        let mut _value: usize = 0;
    }: {
        _value = PalletMixnet::<T>::get_random_range(lower, upper).unwrap();
    } verify {
        ensure!(_value < upper, "_value >= upper");
        ensure!(lower < _value, "_value <= lower");
    }

    shuffle_ciphers_3 {
        let (topic_id, _, _) = setup_shuffle::<T>(3)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&topic_id);
    }

    shuffle_ciphers_10 {
        let (topic_id, _, _) = setup_shuffle::<T>(10)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&topic_id);
    }

    shuffle_ciphers_30 {
        let (topic_id, _, _) = setup_shuffle::<T>(30)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&topic_id);
    }

    shuffle_ciphers_100 {
        let (topic_id, _, _) = setup_shuffle::<T>(100)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&topic_id);
    }

    shuffle_ciphers_1000 {
        let (topic_id, _, _) = setup_shuffle::<T>(1000)?;
    }: {
        let _result = PalletMixnet::<T>::shuffle_ciphers(&topic_id);
    }

    shuffle_proof_3 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(3)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_10 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(10)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_30 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(30)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_100 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(100)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e, e_hat, r, &permutation, &pk);
    }

    shuffle_proof_1000 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(1000)?;
    }: {
        let _result = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e, e_hat, r, &permutation, &pk);
    }

    verify_shuffle_proof_3 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(3)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&vote_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_10 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(10)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&vote_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_30 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(30)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&vote_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_100 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(100)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&vote_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }

    verify_shuffle_proof_1000 {
        let (vote_id, e, e_hat, r, permutation, pk) = setup_shuffle_proof::<T>(1000)?;
        let proof: Proof = PalletMixnet::<T>::generate_shuffle_proof(&vote_id, e.clone(), e_hat.clone(), r, &permutation, &pk)?;
    }: {
        let success = PalletMixnet::<T>::verify_shuffle_proof(&vote_id, proof, e, e_hat, &pk)?;
        ensure!(success, "proof did not verify!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{ExternalityBuilder, TestRuntime};
    use frame_support::assert_ok;

    #[test]
    fn test_benchmarks() {
        let (mut t, _, _) = ExternalityBuilder::build();
        t.execute_with(|| {
            assert_ok!(test_benchmark_store_public_key::<TestRuntime>());
            assert_ok!(test_benchmark_random_range::<TestRuntime>());
            assert_ok!(test_benchmark_shuffle_ciphers_3::<TestRuntime>());
            assert_ok!(test_benchmark_shuffle_proof_3::<TestRuntime>());
            assert_ok!(test_benchmark_verify_shuffle_proof_3::<TestRuntime>());
        });
    }
}
