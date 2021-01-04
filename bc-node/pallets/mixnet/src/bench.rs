#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crypto::helper::Helper;
use crypto::types::PublicKey as ElGamalPK;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use sp_std::vec;

use crate::Module as PalletMixnet;

benchmarks! {
    _{ }

    store_public_key {
        // create the public key
        let (_, _, pk) = Helper::setup_lg_system();

        // create the submitter (i.e. the public key submitter)
        let account: T::AccountId = whitelisted_caller();
        let who = RawOrigin::Signed(account.into());
    }: {
        // store created public key and public parameters
        PalletMixnet::<T>::store_public_key(who.into(), pk.clone().into());
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
            assert_ok!(test_benchmark_test::<TestRuntime>());
            assert_ok!(test_benchmark_sort_vector::<TestRuntime>());
            assert_ok!(test_benchmark_store_public_key::<TestRuntime>());
            assert_ok!(test_benchmark_random_range::<TestRuntime>());
        });
    }
}
