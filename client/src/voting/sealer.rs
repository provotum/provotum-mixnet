use crypto::{
    proofs::re_encryption::ReEncryptionProof,
    types::{Cipher, PublicKey},
};
use serde::{Deserialize, Serialize};
use substrate_subxt::Client;
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct RequestBody {
    pub pk: PublicKey,
    pub cipher: Cipher,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct ResponseBody {
    pub proof: ReEncryptionProof,
    pub cipher: Cipher,
}

async fn init() -> Result<Client<NodeTemplateRuntime>, Error> {
    env_logger::init();
    let url = "ws://127.0.0.1:9944";
    let client = ClientBuilder::<NodeTemplateRuntime>::new()
        .set_url(url)
        .build()
        .await?;
    Ok(client)
}

pub async fn keygen(vote: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    todo!()
}

pub async fn decrypt(vote: String, question: String) -> Result<(), Error> {
    // init substrate client
    let client = init().await?;

    todo!()
}
