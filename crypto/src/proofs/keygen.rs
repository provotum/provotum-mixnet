pub struct KeyGenerationProof;

impl KeyGenerationProof {
    pub fn generate_proof() {}

    pub fn verify_proof() {}
}

#[cfg(test)]
mod tests {
    use crate::{random::Random, types::ElGamalParams};
    use num_bigint::BigUint;

    #[test]
    fn it_should_test_something() {
        let params = ElGamalParams {
          p: BigUint::parse_bytes(b"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC942593", 16).unwrap(),
          g: BigUint::parse_bytes(b"4", 10).unwrap(),
          h: BigUint::parse_bytes(b"9", 10).unwrap(),
      };
        assert!(Random::is_prime(&params.p, 10), "p is not prime!");
        let q = params.q();
        assert!(Random::is_prime(&q, 10), "q is not prime!");
    }
}
