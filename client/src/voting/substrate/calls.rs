use codec::Encode;
use pallet_mixnet::types::{
    Ballot, DecryptedShare, DecryptedShareProof, NrOfShuffles, PublicKey as SubstratePK,
    PublicKeyShare, PublicParameters, Title, Topic, TopicId, VoteId, VotePhase,
};
use substrate_subxt::{Call, EventsDecoder, NodeTemplateRuntime};

#[derive(Encode)]
pub struct CreateVote {
    pub vote_id: VoteId,
    pub title: Title,
    pub params: PublicParameters,
    pub topics: Vec<Topic>,
    pub batch_size: u64,
}

impl Call<NodeTemplateRuntime> for CreateVote {
    const MODULE: &'static str = "PalletMixnet";
    const FUNCTION: &'static str = "create_vote";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {
        _decoder.register_type_size::<VoteId>("VoteId");
        _decoder.register_type_size::<Title>("Title");
        _decoder.register_type_size::<PublicParameters>("PublicParameters");
        _decoder.register_type_size::<Vec<Topic>>("Vec<Topic>");
        _decoder.register_type_size::<u64>("batch_size");
    }
}

#[derive(Encode)]
pub struct StorePublicKey {
    pub vote_id: VoteId,
    pub pk: SubstratePK,
}

impl Call<NodeTemplateRuntime> for StorePublicKey {
    const MODULE: &'static str = "PalletMixnet";
    const FUNCTION: &'static str = "store_public_key";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {
        _decoder.register_type_size::<VoteId>("VoteId");
        _decoder.register_type_size::<SubstratePK>("SubstratePK");
    }
}

#[derive(Encode)]
pub struct StorePublicKeyShare {
    pub vote_id: VoteId,
    pub pk_share: PublicKeyShare,
}

impl Call<NodeTemplateRuntime> for StorePublicKeyShare {
    const MODULE: &'static str = "PalletMixnet";
    const FUNCTION: &'static str = "store_public_key_share";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {
        _decoder.register_type_size::<VoteId>("VoteId");
        _decoder.register_type_size::<PublicKeyShare>("PublicKeyShare");
    }
}

#[derive(Encode)]
pub struct CombinePublicKeyShares {
    pub vote_id: VoteId,
}

impl Call<NodeTemplateRuntime> for CombinePublicKeyShares {
    const MODULE: &'static str = "PalletMixnet";
    const FUNCTION: &'static str = "combine_public_key_shares";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {
        _decoder.register_type_size::<VoteId>("VoteId");
    }
}

#[derive(Encode)]
pub struct SetVotePhase {
    pub vote_id: VoteId,
    pub vote_phase: VotePhase,
}

impl Call<NodeTemplateRuntime> for SetVotePhase {
    const MODULE: &'static str = "PalletMixnet";
    const FUNCTION: &'static str = "set_vote_phase";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {
        _decoder.register_type_size::<VoteId>("VoteId");
        _decoder.register_type_size::<VotePhase>("VotePhase");
    }
}

#[derive(Encode)]
pub struct CastBallot {
    pub vote_id: VoteId,
    pub ballot: Ballot,
}

impl Call<NodeTemplateRuntime> for CastBallot {
    const MODULE: &'static str = "PalletMixnet";
    const FUNCTION: &'static str = "cast_ballot";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {
        _decoder.register_type_size::<VoteId>("VoteId");
        _decoder.register_type_size::<Ballot>("Ballot");
    }
}

#[derive(Encode)]
pub struct SubmitPartialDecryption {
    pub vote_id: VoteId,
    pub topic_id: TopicId,
    pub shares: Vec<DecryptedShare>,
    pub proof: DecryptedShareProof,
    pub nr_of_shuffles: NrOfShuffles,
}

impl Call<NodeTemplateRuntime> for SubmitPartialDecryption {
    const MODULE: &'static str = "PalletMixnet";
    const FUNCTION: &'static str = "submit_decrypted_shares";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {
        _decoder.register_type_size::<VoteId>("VoteId");
        _decoder.register_type_size::<TopicId>("TopicId");
        _decoder.register_type_size::<Vec<DecryptedShare>>("Vec<DecryptedShare>");
        _decoder.register_type_size::<DecryptedShareProof>("DecryptedShareProof");
        _decoder.register_type_size::<NrOfShuffles>("NrOfShuffles");
    }
}

#[derive(Encode)]
pub struct CombineDecryptedShares {
    vote_id: VoteId,
    topic_id: TopicId,
    encoded: bool,
    nr_of_shuffles: NrOfShuffles,
}

impl Call<NodeTemplateRuntime> for CombineDecryptedShares {
    const MODULE: &'static str = "PalletMixnet";
    const FUNCTION: &'static str = "combine_decrypted_shares";
    fn events_decoder(_decoder: &mut EventsDecoder<NodeTemplateRuntime>) {
        _decoder.register_type_size::<VoteId>("VoteId");
        _decoder.register_type_size::<TopicId>("TopicId");
        _decoder.register_type_size::<bool>("bool");
        _decoder.register_type_size::<NrOfShuffles>("NrOfShuffles");
    }
}
