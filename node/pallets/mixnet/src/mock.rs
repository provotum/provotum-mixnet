use crate as pallet_mixnet;
use crate::Call;
use codec::alloc::sync::Arc;
use codec::Decode;
use frame_support::{
    dispatch::Weight, impl_outer_event, impl_outer_origin, parameter_types,
};
use hex_literal::hex;
use pallet_timestamp;
use parking_lot::RwLock;
use sp_core::{
    offchain::{
        testing::{self, OffchainState, PoolState},
        OffchainExt, TransactionPoolExt,
    },
    sr25519::{self, Signature},
    testing::KeyStore,
    traits::KeystoreExt,
    H256,
};
use sp_io::TestExternalities;
use sp_runtime::{
    testing::{Header, TestXt},
    traits::{BlakeTwo256, IdentityLookup, Verify},
    Perbill,
};

impl_outer_origin! {
    pub enum Origin for TestRuntime {}
}

impl_outer_event! {
    pub enum TestEvent for TestRuntime {
        // events of crate: pallet_mixnet
        frame_system<T>,
        pallet_mixnet<T>,
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRuntime;

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = 1024;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
}

// The TestRuntime implements two pallet/frame traits: system, and simple_event
impl frame_system::Trait for TestRuntime {
    type BaseCallFilter = ();
    type Origin = Origin;
    type Index = u64;
    type Call = ();
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = sr25519::Public;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = TestEvent;
    type BlockHashCount = BlockHashCount;
    type MaximumBlockWeight = MaximumBlockWeight;
    type DbWeight = ();
    type BlockExecutionWeight = ();
    type ExtrinsicBaseWeight = ();
    type MaximumExtrinsicWeight = MaximumBlockWeight;
    type MaximumBlockLength = MaximumBlockLength;
    type AvailableBlockRatio = AvailableBlockRatio;
    type Version = ();
    type PalletInfo = ();
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = 3000;
}

impl pallet_timestamp::Trait for TestRuntime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

// --- mocking offchain-worker trait

pub type TestExtrinsic = TestXt<Call<TestRuntime>, ()>;

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for TestRuntime
where
    Call<TestRuntime>: From<LocalCall>,
{
    fn create_transaction<
        C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>,
    >(
        call: Call<TestRuntime>,
        _public: <Signature as Verify>::Signer,
        _account: <TestRuntime as frame_system::Trait>::AccountId,
        index: <TestRuntime as frame_system::Trait>::Index,
    ) -> Option<(
        Call<TestRuntime>,
        <TestExtrinsic as sp_runtime::traits::Extrinsic>::SignaturePayload,
    )> {
        Some((call, (index, ())))
    }
}

impl frame_system::offchain::SigningTypes for TestRuntime {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for TestRuntime
where
    Call<TestRuntime>: From<C>,
{
    type OverarchingCall = Call<TestRuntime>;
    type Extrinsic = TestExtrinsic;
}

pub type System = frame_system::Module<TestRuntime>;

////////////////////////////////////////
// Mock Implementation of pallet_mixnet
parameter_types! {
    pub const TestBlockDuration: u64 = 1;
}

impl pallet_mixnet::Trait for TestRuntime {
    type Call = Call<TestRuntime>;
    type Event = TestEvent;
    type AuthorityId = pallet_mixnet::keys::TestAuthId;
    type BlockDuration = TestBlockDuration;
}

pub type OffchainModule = pallet_mixnet::Module<TestRuntime>;

pub struct ExternalityBuilder;

impl ExternalityBuilder {
    fn initialize_test_authorities() -> (
        Vec<<TestRuntime as frame_system::Trait>::AccountId>,
        Vec<<TestRuntime as frame_system::Trait>::AccountId>,
    ) {
        // use Alice as VotingAuthority
        let alice_account_id: [u8; 32] =
            hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
                .into();

        let voting_authority: <TestRuntime as frame_system::Trait>::AccountId =
            <TestRuntime as frame_system::Trait>::AccountId::decode(
                &mut &alice_account_id[..],
            )
            .unwrap();

        // Use Bob, Charlie, Dave as Sealers
        let bob_account_id: [u8; 32] =
            hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")
                .into();

        let sealer1: <TestRuntime as frame_system::Trait>::AccountId =
            <TestRuntime as frame_system::Trait>::AccountId::decode(
                &mut &bob_account_id[..],
            )
            .unwrap();

        let charlie_account_id: [u8; 32] =
            hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22")
                .into();

        let sealer2: <TestRuntime as frame_system::Trait>::AccountId =
            <TestRuntime as frame_system::Trait>::AccountId::decode(
                &mut &charlie_account_id[..],
            )
            .unwrap();

        // let dave_account_id: [u8; 32] =
        //     hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eebbf2314649965fe22")
        //         .into();

        // let sealer3: <TestRuntime as frame_system::Trait>::AccountId =
        //     <TestRuntime as frame_system::Trait>::AccountId::decode(&mut &dave_account_id[..])
        //         .unwrap();

        let voting_authorities = vec![voting_authority];
        // let sealers = vec![sealer1, sealer2, sealer3];
        let sealers = vec![sealer1, sealer2];
        (voting_authorities, sealers)
    }

    pub fn build() -> (
        TestExternalities,
        Arc<RwLock<PoolState>>,
        Arc<RwLock<OffchainState>>,
    ) {
        const PHRASE: &str =
            "expire stage crawl shell boss any story swamp skull yellow bamboo copy";

        let (offchain, offchain_state) = testing::TestOffchainExt::new();
        let (pool, pool_state) = testing::TestTransactionPoolExt::new();
        let keystore = KeyStore::new();
        keystore
            .write()
            .sr25519_generate_new(
                pallet_mixnet::keys::KEY_TYPE,
                Some(&format!("{}/hunter1", PHRASE)),
            )
            .unwrap();

        let mut storage = frame_system::GenesisConfig::default()
            .build_storage::<TestRuntime>()
            .unwrap();

        let (voting_authorities, sealers) = Self::initialize_test_authorities();

        super::GenesisConfig::<TestRuntime> {
            voting_authorities,
            sealers,
        }
        .assimilate_storage(&mut storage)
        .unwrap();

        let mut t = TestExternalities::from(storage);
        t.register_extension(OffchainExt::new(offchain));
        t.register_extension(TransactionPoolExt::new(pool));
        t.register_extension(KeystoreExt(keystore));
        t.execute_with(|| System::set_block_number(1));
        (t, pool_state, offchain_state)
    }
}
