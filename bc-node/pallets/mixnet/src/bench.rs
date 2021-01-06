#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::types::PublicParameters;
use crypto::{encryption::ElGamal, helper::Helper, types::PublicKey as ElGamalPK};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use hex_literal::hex;
use sp_std::vec;

use crate::Module as PalletMixnet;

fn setup_public_key<T: Trait>(pk: SubstratePK) {
    // create the submitter (i.e. the public key submitter)
    let account: T::AccountId = whitelisted_caller();
    let who = RawOrigin::Signed(account.into());

    // store created public key and public parameters
    PalletMixnet::<T>::store_public_key(who.into(), pk);
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

fn setup_shuffle<T: Trait>(size: usize) -> Result<Vec<u8>, &'static str> {
    // setup
    let (params, _, pk) = Helper::setup_lg_system();
    let (vote_id, topic_id) = setup_vote::<T>(params.into())?;
    setup_public_key::<T>(pk.clone().into());

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
    Ok(topic_id)
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
        PalletMixnet::<T>::store_public_key(who.into(), pk.clone().into())
    }
    verify {
        // fetch the public key from the chain
        let pk_from_chain: ElGamalPK = PalletMixnet::<T>::public_key().unwrap().into();
        ensure!(pk_from_chain == pk, "fail pk_from_chain != pk");
    }

    random_range {
        let lower: usize = 0;
        let upper: usize = 100;
        let mut value: usize = 0;
    }: {
        value = PalletMixnet::<T>::get_random_range(lower, upper).unwrap();
    } verify {
        ensure!(value < upper, "value >= upper");
        ensure!(lower < value, "value <= lower");
    }

    shuffle_ciphers_three_votes {
        let topic_id = setup_shuffle::<T>(3)?;
    }: {
        PalletMixnet::<T>::shuffle_ciphers(&topic_id)
    }

    shuffle_ciphers_thirty_votes {
        let topic_id = setup_shuffle::<T>(30)?;
    }: {
        PalletMixnet::<T>::shuffle_ciphers(&topic_id)
    }

    shuffle_ciphers_onehundred_votes {
        let topic_id = setup_shuffle::<T>(100)?;
    }: {
        PalletMixnet::<T>::shuffle_ciphers(&topic_id)
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
            assert_ok!(test_benchmark_shuffle_ciphers_three_votes::<TestRuntime>());
        });
    }
}
