use sp_core::sr25519::Signature as Sr25519Signature;
use sp_runtime::app_crypto::{app_crypto, sr25519};
use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// them with the pallet-specific identifier.
use sp_core::crypto::KeyTypeId;

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for its crypto keys.
/// When an offchain worker is signing transactions it's going to request keys from type
/// `KeyTypeId` via the keystore to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");

app_crypto!(sr25519, KEY_TYPE);

pub struct TestAuthId;

// implemented for pallet-mixnet
impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
    type RuntimeAppPublic = Public;
    type GenericSignature = sp_core::sr25519::Signature;
    type GenericPublic = sp_core::sr25519::Public;
}

// implemented for mock runtime in test
impl
    frame_system::offchain::AppCrypto<
        <Sr25519Signature as Verify>::Signer,
        Sr25519Signature,
    > for TestAuthId
{
    type RuntimeAppPublic = Public;
    type GenericSignature = sp_core::sr25519::Signature;
    type GenericPublic = sp_core::sr25519::Public;
}
