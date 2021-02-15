use codec::Encode;
use pallet_mixnet::types::{PublicParameters, Topic};

#[derive(Encode)]
pub struct CreateVoteCall {
    pub vote_id: Vec<u8>,
    pub title: Vec<u8>,
    pub params: PublicParameters,
    pub topics: Vec<Topic>,
}
