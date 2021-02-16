use codec::Encode;
use pallet_mixnet::types::{Cipher, NrOfShuffles, TopicId, VoteId};
use pallet_mixnet::Trait;
use std::marker::PhantomData;
use substrate_subxt::{
    sp_core::storage::StorageKey, system::System, Metadata, MetadataError, NodeTemplateRuntime,
    Store,
};

#[derive(Clone, Debug, Eq, Encode, PartialEq)]
pub struct VotesStore {}

impl Store<NodeTemplateRuntime> for VotesStore {
    /// Module name.
    const MODULE: &'static str = "PalletMixnet";
    /// Field name.
    const FIELD: &'static str = "VoteIds";
    /// Return type.
    type Returns = Vec<VoteId>;
    /// Returns the key prefix for storage maps
    fn prefix(metadata: &Metadata) -> Result<StorageKey, MetadataError> {
        Ok(metadata
            .module(Self::MODULE)?
            .storage(Self::FIELD)?
            .prefix())
    }
    /// Returns the `StorageKey`.
    fn key(&self, metadata: &Metadata) -> Result<StorageKey, MetadataError> {
        Ok(metadata
            .module(Self::MODULE)?
            .storage(Self::FIELD)?
            .plain()?
            .key())
    }
    /// Returns the default value.
    fn default(&self, metadata: &Metadata) -> Result<Self::Returns, MetadataError> {
        Ok(metadata
            .module(Self::MODULE)?
            .storage(Self::FIELD)?
            .default()?)
    }
}

#[derive(Clone, Debug, Eq, Encode, PartialEq)]
pub struct CiphersStore {
    pub topic_id: TopicId,
    pub nr_of_shuffles: NrOfShuffles,
}

impl Store<NodeTemplateRuntime> for CiphersStore {
    /// Module name.
    const MODULE: &'static str = "PalletMixnet";
    /// Field name.
    const FIELD: &'static str = "Ciphers";
    /// Return type.
    type Returns = Vec<VoteId>;
    /// Returns the key prefix for storage maps
    fn prefix(metadata: &Metadata) -> Result<StorageKey, MetadataError> {
        Ok(metadata
            .module(Self::MODULE)?
            .storage(Self::FIELD)?
            .prefix())
    }
    /// Returns the `StorageKey`.
    fn key(&self, metadata: &Metadata) -> Result<StorageKey, MetadataError> {
        let storage = metadata.module(Self::MODULE)?.storage(Self::FIELD)?;
        let item = storage.double_map()?;
        Ok(item.key(&self.topic_id, &self.nr_of_shuffles))
    }
    /// Returns the default value.
    fn default(&self, metadata: &Metadata) -> Result<Self::Returns, MetadataError> {
        Ok(metadata
            .module(Self::MODULE)?
            .storage(Self::FIELD)?
            .default()?)
    }
}
