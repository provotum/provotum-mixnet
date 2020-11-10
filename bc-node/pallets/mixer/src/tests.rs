use crate::mock::*;
use crate::*;
use codec::Decode;
use frame_support::assert_ok;
use sp_std::if_std;

#[test]
fn test_submit_number_signed_works() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        // call submit_number_signed
        let num = 32;
        let acct: <TestRuntime as system::Trait>::AccountId = Default::default();
        assert_ok!(OffchainModule::submit_number_signed(
            Origin::signed(acct),
            num
        ));
        // A number is inserted to <Numbers> vec
        assert_eq!(<Numbers>::get(), vec![num]);
        // An event is emitted
        assert!(System::events()
            .iter()
            .any(|er| er.event == TestEvent::offchain_mixer(RawEvent::NewNumber(Some(acct), num))));

        // Insert another number
        let num2 = num * 2;
        assert_ok!(OffchainModule::submit_number_signed(
            Origin::signed(acct),
            num2
        ));
        // A number is inserted to <Numbers> vec
        assert_eq!(<Numbers>::get(), vec![num, num2]);
    });
}

#[test]
fn test_offchain_signed_tx() {
    let (mut t, pool_state, _) = ExternalityBuilder::build();

    t.execute_with(|| {
        // Setup
        let num = 32;
        OffchainModule::offchain_signed_tx(num).unwrap();

        // Verify
        let tx = pool_state.write().transactions.pop().unwrap();
        assert!(pool_state.read().transactions.is_empty());
        let tx = TestExtrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature.unwrap().0, 0);
        assert_eq!(tx.call, Call::submit_number_signed(num));
    });
}

#[test]
fn test_offchain_unsigned_tx() {
    let (mut t, pool_state, _) = ExternalityBuilder::build();

    t.execute_with(|| {
        // when
        let num = 32;
        OffchainModule::offchain_unsigned_tx(num).unwrap();
        // then
        let tx = pool_state.write().transactions.pop().unwrap();
        assert!(pool_state.read().transactions.is_empty());
        let tx = TestExtrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature, None);
        assert_eq!(tx.call, Call::submit_number_unsigned(num));
    });
}

#[test]
fn test_offchain_signed_tx_random_number() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let acct: <TestRuntime as system::Trait>::AccountId = Default::default();
        let origin = Origin::signed(acct);
        let tx_result = OffchainModule::random(origin);
        assert_ok!(tx_result);
    });
}

#[test]
fn test_get_random_bytes() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let size: usize = 32;
        let random = OffchainModule::get_random_bytes(size).unwrap();
        assert_eq!(random.len(), size);
    });
}

#[test]
fn test_get_random_number_less_than() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let upper_bound: BigUint = BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
        let random = OffchainModule::get_random_less_than(&upper_bound).unwrap();
        assert!(random < upper_bound);
    });
}

#[test]
fn test_get_random_number_less_than_should_panic_number_is_zero() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let upper_bound: BigUint = BigUint::parse_bytes(b"0", 10).unwrap();
        OffchainModule::get_random_less_than(&upper_bound).expect_err(
            "The returned value should be: '<Error<T>>::RandomnessUpperBoundZeroError'",
        );
    });
}

#[test]
fn test_get_random_bigunint_range() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: BigUint = BigUint::parse_bytes(b"0", 10).unwrap();
        let upper: BigUint = BigUint::parse_bytes(b"10981023801283012983912312", 10).unwrap();
        let value = OffchainModule::get_random_bigunint_range(&lower, &upper).unwrap();
        
        assert!(value < upper);
        assert!(lower < value);
        
        if_std! {
            println!("random value in range. lower: {:?}, upper: {:?}, value: {:?}", lower, upper, value);
        }
    });
}

#[test]
fn test_get_random_bigunint_range_upper_is_zero() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: BigUint = BigUint::parse_bytes(b"0", 10).unwrap();
        let upper: BigUint = BigUint::parse_bytes(b"0", 10).unwrap();
        OffchainModule::get_random_bigunint_range(&lower, &upper)
            .expect_err("The returned value should be: '<Error<T>>::RandomRangeError'");
    });
}

#[test]
fn test_get_random_bigunint_range_upper_is_not_larger_than_lower() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: BigUint = BigUint::parse_bytes(b"5", 10).unwrap();
        let upper: BigUint = BigUint::parse_bytes(b"5", 10).unwrap();
        OffchainModule::get_random_bigunint_range(&lower, &upper)
            .expect_err("The returned value should be: '<Error<T>>::RandomRangeError'");
    });
}

#[test]
fn test_get_random_range() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: usize = 0;
        let upper: usize = 100;
        let value = OffchainModule::get_random_range(lower, upper).unwrap();
        
        assert!(value < upper);
        assert!(lower < value);
        
        if_std! {
            println!("random value in range. lower: {:?}, upper: {:?}, value: {:?}", lower, upper, value);
        }
    });
}

#[test]
fn test_get_random_range_upper_is_zero_error() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: usize = 0;
        let upper: usize = 0;
        OffchainModule::get_random_range(lower, upper).expect_err("The returned value should be: '<Error<T>>::RandomRangeError'");
    });
}

#[test]
fn test_get_random_range_upper_is_not_larger_than_lower_error() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let lower: usize = 5;
        let upper: usize = 5;
        OffchainModule::get_random_range(lower, upper).expect_err("The returned value should be: '<Error<T>>::RandomRangeError'");
    });
}

#[test]
fn test_generate_permutation_size_zero_error() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let size = 0;
        OffchainModule::generate_permutation(size).expect_err("The returned value should be: '<Error<T>>::PermutationSizeZeroError'");
    });
}

#[test]
fn test_should_generate_a_permutation_size_three() {
    let (mut t, _, _) = ExternalityBuilder::build();
    t.execute_with(|| {
        let size = 3;
        let permutation = OffchainModule::generate_permutation(size).unwrap();

        // check that the permutation has the expected size
        assert!(permutation.len() == (size as usize));

        // check that 0, 1, 2 occur at least once each
        assert!(permutation.iter().any(|&value| value == 0));
        assert!(permutation.iter().any(|&value| value == 1));
        assert!(permutation.iter().any(|&value| value == 2));
    });
}
