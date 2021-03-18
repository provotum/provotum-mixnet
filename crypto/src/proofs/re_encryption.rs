#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct ReEncryptionProof {}

impl ReEncryptionProof {
    /// Comment this function
    pub fn generate() -> ReEncryptionProof {
        unimplemented!()
    }

    /// Comment this Function
    pub fn verify() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_should_test() {
        println!("hi there");
    }
}
