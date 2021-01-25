use crate::types::{Cipher, ModuloOperations, PrivateKey, PublicKey};
use alloc::vec::Vec;
use num_bigint::BigUint;
use num_traits::Zero;

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub struct ElGamal;

impl ElGamal {
    /// Returns an ElGamal Encryption of a message
    /// - (a, b) = (g^r, h^r * g^m)
    ///
    /// ## Arguments
    ///
    /// * `m`  - The message (BigUint)
    /// * `r`  - The random number used to encrypt_encode the vote
    /// * `pk` - The public key used to encrypt_encode the vote
    pub fn encrypt_encode(m: &BigUint, r: &BigUint, pk: &PublicKey) -> Cipher {
        let g = &pk.params.g;
        let p = &pk.params.p;
        let h = &pk.h;

        // a = g^r
        let a = g.modpow(r, p);

        // encode the message: g^m (exponential elgamal)
        let enc_m = ElGamal::encode_message(m, g, p);

        // b = h^r * g^m
        let h_pow_r = h.modpow(r, p);
        let b = h_pow_r.modmul(&enc_m, p);

        Cipher { a, b }
    }

    /// Returns the plaintext contained in an ElGamal Encryption
    /// - mh = b * (a^x)^-1
    /// - m = log mh = log g^m
    ///
    /// ## Arguments
    ///
    /// * `cipher` - The ElGamal Encryption (a: BigUint, b: BigUint)
    /// * `sk`     - The private key used to decrypt the vote
    pub fn decrypt(cipher: &Cipher, sk: &PrivateKey) -> BigUint {
        let a = &cipher.a;
        let b = &cipher.b;

        let g = &sk.params.g;
        let p = &sk.params.p;
        let x = &sk.x;

        // a = g^r -> a^x = g^r^x
        let s = a.modpow(x, p);

        // compute multiplicative inverse of s
        let s_1 = s.invmod(p).expect("cannot compute mod_inverse!");

        // b = g^m*h^r -> mh = b * s^-1
        let mh = b.modmul(&s_1, p);

        // brute force discrete logarithm
        ElGamal::decode_message(&mh, g, p)
    }

    /// Encodes a plain-text message to be used in an explonential ElGamal scheme
    /// Returns encoded_message = g^m.
    ///
    /// ## Arguments
    ///
    /// * `m` - The message  (BigUint)
    /// * `g` - The generator of the cyclic group Z_p (BigUint)
    /// * `p` - The group modulus p (BigUint)
    fn encode_message(m: &BigUint, g: &BigUint, p: &BigUint) -> BigUint {
        g.modpow(m, p)
    }

    /// Decodes an explonential ElGamal scheme encoded message by brute forcing the discrete lograithm.
    /// The goal is to find: encoded_message = g^m by iterating through different values for m.
    ///
    /// ## Arguments
    ///
    /// * `encoded_message` - The encoded message: g^m (BigUint)
    /// * `g` - The generator of the cyclic group Z_p (BigUint)
    /// * `p` - The group modulus p (BigUint)
    fn decode_message(encoded_message: &BigUint, g: &BigUint, p: &BigUint) -> BigUint {
        let one = 1u32;
        let mut message = BigUint::zero();

        // *encoded_message = dereference 'encoded_message' to get the value
        // brute force the discrete logarithm
        while *encoded_message != ElGamal::encode_message(&message, g, p) {
            message += one
        }
        message
    }

    /// Homomorphically adds two ElGamal encryptions.
    /// Returns an ElGamal encryption.
    ///
    /// ## Arguments
    ///
    /// * `this`   - a Cipher { a, b } (ElGamal encryption)
    /// * `other`  - a Cipher { a, b } (ElGamal encryption)
    /// * `p` - The group modulus p (BigUint)    
    pub fn add(this: &Cipher, other: &Cipher, p: &BigUint) -> Cipher {
        let (a1, b1) = (this.a.clone(), this.b.clone());
        let (a2, b2) = (other.a.clone(), other.b.clone());
        Cipher {
            a: a1.modmul(&a2, p),
            b: b1.modmul(&b2, p),
        }
    }

    /// Returns an ElGamal re-encryption of a message
    /// - message:      (a, b)   = (g^r, h^r * g^m)
    /// - reencryption: (a', b') = (a * g^r', b * h^r') = (g^(r * r'), h^(r * r') * g^m)
    ///
    /// ## Arguments
    ///
    /// * `cipher` - An ElGamal Encryption { a: BigUint, b: BigUint }
    /// * `r`      - The random number used to re-encrypt_encode the vote    
    /// * `pk`     - The public key used to re-encrypt_encode the vote
    pub fn re_encrypt(cipher: &Cipher, r: &BigUint, pk: &PublicKey) -> Cipher {
        let p = &pk.params.p;
        let a_ = pk.params.g.modpow(r, p);
        let b_ = pk.h.modpow(r, p);
        Cipher {
            a: cipher.a.modmul(&a_, p),
            b: cipher.b.modmul(&b_, p),
        }
    }

    /// Returns an ElGamal re-encryption of a message
    /// - message:      (a, b)      = (g^r, h^r * g^m)
    /// - zero:         (a', b')    = (g^r', h^r' * g^0) = (g^r', h^r')
    /// - reencryption: (a'', b'')  = (a * a', b * b')     = (g^(r * r'), h^(r * r') * g^m)
    ///
    /// Note: The g^0 = 1 and, therefore, can be dropped. Re-encryption -> homomorphic addition with zero.
    ///
    /// ## Arguments
    ///
    /// * `cipher` - An ElGamal Encryption { a: BigUint, b: BigUint }
    /// * `r`      - The random number used to re-encrypt_encode the vote    
    /// * `pk`     - The public key used to re-encrypt_encode the vote
    pub fn re_encrypt_via_addition(cipher: &Cipher, r: &BigUint, pk: &PublicKey) -> Cipher {
        let zero = Self::encrypt_encode(&BigUint::zero(), &r, &pk);
        Self::add(cipher, &zero, &pk.params.p)
    }

    /// Returns a shuffled (permuted & re-encrypted) list of ElGamal encryptions.
    ///
    /// ## Arguments
    ///
    /// * `cipher` - An ElGamal Encryption { a: BigUint, b: BigUint }
    /// * `r`      - The random number used to re-encrypt_encode the vote    
    /// * `pk`     - The public key used to re-encrypt_encode the vote
    pub fn shuffle(
        encryptions: &[Cipher],
        permutation: &[usize],
        randoms: &[BigUint],
        pk: &PublicKey,
    ) -> Vec<(Cipher, BigUint, usize)> {
        assert!(
            encryptions.len() == randoms.len(),
            "encryptions and randoms need to have the same length!"
        );
        assert!(
            encryptions.len() == permutation.len(),
            "encryptions and permutation need to have the same length!"
        );
        assert!(!encryptions.is_empty(), "vectors cannot be empty!");

        // generate a permutatinon of size of the encryptions
        let mut re_encryptions: Vec<(Cipher, BigUint, usize)> = Vec::new();

        for entry in permutation {
            // get the encryption and the random value at the permutation position
            let encryption = &encryptions[*entry];
            let random = &randoms[*entry];

            // re-encrypt_encode
            let re_encryption = ElGamal::re_encrypt(&encryption, &random, pk);
            re_encryptions.push((re_encryption, random.clone(), *entry));
        }
        re_encryptions
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encryption::ElGamal, helper::Helper, random::Random, types::Cipher, types::ElGamalParams,
        types::PublicKey,
    };
    use alloc::vec::Vec;
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    #[test]
    fn it_should_encode_a_message() {
        let params = ElGamalParams {
            p: BigUint::from(7u32),
            g: BigUint::from(2u32),
            h: BigUint::from(3u32),
        };
        let message = BigUint::from(3u32);
        let encoded_message = ElGamal::encode_message(&message, &params.g, &params.p);

        // g^3 mod 7 -> g = 4, 4^3 mod 7 = 64 mod 7 = 1
        assert_eq!(encoded_message, BigUint::from(1u32));
    }

    #[test]
    fn it_should_decode_zero() {
        let (params, _, _) = Helper::setup_sm_system();
        let zero = BigUint::zero();
        let message = zero.clone();
        let encoded_message = ElGamal::encode_message(&message, &params.g, &params.p);
        let decoded_message = ElGamal::decode_message(&encoded_message, &params.g, &params.p);
        assert_eq!(zero, decoded_message);
    }

    #[test]
    fn it_should_decode_one() {
        let (params, _, _) = Helper::setup_sm_system();
        let one = BigUint::one();
        let message = one.clone();
        let encoded_message = ElGamal::encode_message(&message, &params.g, &params.p);
        let decoded_message = ElGamal::decode_message(&encoded_message, &params.g, &params.p);
        assert_eq!(one, decoded_message);
    }

    #[test]
    fn it_should_decode_25() {
        let (params, _, _) = Helper::setup_sm_system();

        // choose a message m > 1 && m < q
        let nine = BigUint::from(9u32);
        let message = nine.clone();
        let encoded_message = ElGamal::encode_message(&message, &params.g, &params.p);
        let decoded_message = ElGamal::decode_message(&encoded_message, &params.g, &params.p);
        assert_eq!(nine, decoded_message);
    }

    #[test]
    fn it_should_encrypt() {
        let params = ElGamalParams {
            p: BigUint::from(7u32),
            g: BigUint::from(4u32),
            h: BigUint::from(3u32),
        };
        let pk = PublicKey {
            h: BigUint::from(2u32),
            params,
        };

        // the value of the message: 1
        let message = BigUint::from(1u32);

        // a new random value for the encryption
        let r_ = BigUint::from(1u32);

        // encrypt_encode the message
        let encrypted_message = ElGamal::encrypt_encode(&message, &r_, &pk);

        // check that a = g^r_ -> g = 4 -> 4^1 mod 7 = 4
        assert_eq!(encrypted_message.a, BigUint::from(4u32));

        // check that b = h^r_ * g^m = (g^r)^r_ * g^m
        // b = ((4^2)^1 mod 7 * 4^1 mod 7) mod 7
        // b = (16 mod 7 * 4 mod 7) mod 7
        // b = (2 * 4) mod 7 = 1
        assert_eq!(encrypted_message.b, BigUint::from(1u32));
    }

    #[test]
    fn it_should_encrypt_decrypt_two() {
        let (_, sk, pk) = Helper::setup_sm_system();

        // the value of the message: 2
        let message = BigUint::from(2u32);

        // a new random value for the encryption
        let r_ = BigUint::from(5u32);

        // encrypt_encode the message
        let encrypted_message = ElGamal::encrypt_encode(&message, &r_, &pk);

        // decrypt the encrypted_message & check that the messages are equal
        let decrypted_message = ElGamal::decrypt(&encrypted_message, &sk);
        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn it_should_add_two_zeros() {
        let (params, sk, pk) = Helper::setup_sm_system();
        let zero = BigUint::zero();

        // encryption of zero
        let r_one = BigUint::from(7u32);
        let this = ElGamal::encrypt_encode(&zero, &r_one, &pk);

        // encryption of zero
        let r_two = BigUint::from(5u32);
        let other = ElGamal::encrypt_encode(&zero, &r_two, &pk);

        // add both encryptions: 0 + 0
        let addition = ElGamal::add(&this, &other, &params.p);

        // decrypt result: 0
        let decrypted_addition = ElGamal::decrypt(&addition, &sk);
        assert_eq!(decrypted_addition, zero);
    }

    #[test]
    fn it_should_add_one_and_zero() {
        let (params, sk, pk) = Helper::setup_sm_system();
        let zero = BigUint::zero();
        let one = BigUint::one();

        // encryption of zero
        let r_one = BigUint::from(7u32);
        let this = ElGamal::encrypt_encode(&zero, &r_one, &pk);

        // encryption of one
        let r_two = BigUint::from(5u32);
        let other = ElGamal::encrypt_encode(&one, &r_two, &pk);

        // add both encryptions: 0 + 1
        let addition = ElGamal::add(&this, &other, &params.p);

        // decrypt result: 1
        let decrypted_addition = ElGamal::decrypt(&addition, &sk);
        assert_eq!(decrypted_addition, one);
    }

    #[test]
    fn it_should_add_two_ones() {
        let (params, sk, pk) = Helper::setup_sm_system();
        let one = BigUint::one();
        let expected_result = BigUint::from(2u32);

        // encryption of one
        let r_one = BigUint::from(7u32);
        let this = ElGamal::encrypt_encode(&one, &r_one, &pk);

        // encryption of one
        let r_two = BigUint::from(5u32);
        let other = ElGamal::encrypt_encode(&one, &r_two, &pk);

        // add both encryptions: 1 + 1
        let addition = ElGamal::add(&this, &other, &params.p);

        // decrypt result: 2
        let decrypted_addition = ElGamal::decrypt(&addition, &sk);
        assert_eq!(decrypted_addition, expected_result);
    }

    #[test]
    fn it_should_add_many_and_result_equals_five() {
        let (params, sk, pk) = Helper::setup_md_system();

        let q = params.q();
        let zero = BigUint::zero();
        let one = BigUint::one();
        let expected_result = BigUint::from(5u32);

        // start with an encryption of zero
        // use a random number < q
        let r = Random::get_random_less_than(&q);
        let mut base = ElGamal::encrypt_encode(&zero, &r, &pk);

        // add five encryptions of one
        for _ in 0..5 {
            let r = Random::get_random_less_than(&q);
            let encryption_of_one = ElGamal::encrypt_encode(&one, &r, &pk);
            base = ElGamal::add(&base, &encryption_of_one, &params.p);
        }

        // add five encryptions of zero
        for _ in 0..5 {
            let r = Random::get_random_less_than(&q);
            let encryption_of_zero = ElGamal::encrypt_encode(&zero, &r, &pk);
            base = ElGamal::add(&base, &encryption_of_zero, &params.p);
        }

        // decrypt result: 5
        let decrypted_addition = ElGamal::decrypt(&base, &sk);
        assert_eq!(decrypted_addition, expected_result);
    }

    #[test]
    fn it_should_re_encrypt_five() {
        let (params, sk, pk) = Helper::setup_md_system();

        let q = params.q();
        let five = BigUint::from(5u32);

        // use a random number < q
        let r = Random::get_random_less_than(&q);
        let encrypted_five = ElGamal::encrypt_encode(&five, &r, &pk);

        // re-encryption + check that encryption != re-encryption
        let r_ = Random::get_random_less_than(&q);
        let re_encrypted_five = ElGamal::re_encrypt(&encrypted_five, &r_, &pk);
        assert!(encrypted_five != re_encrypted_five);

        // check that decryption is still the same as the initial value
        let decrypted_re_encryption = ElGamal::decrypt(&re_encrypted_five, &sk);
        assert_eq!(decrypted_re_encryption, five);
    }

    #[test]
    fn it_should_re_encrypt_five_by_addition() {
        let (params, sk, pk) = Helper::setup_md_system();

        let q = params.q();
        let five = BigUint::from(5u32);

        // use a random number < q
        let r = Random::get_random_less_than(&q);
        let encrypted_five = ElGamal::encrypt_encode(&five, &r, &pk);
        let r_ = Random::get_random_less_than(&q);

        // homomorphic addition with zero: 5 + 0 = 5 + check that encryption != re-encryption
        let re_encrypted_addition = ElGamal::re_encrypt_via_addition(&encrypted_five, &r_, &pk);
        assert!(encrypted_five != re_encrypted_addition);

        // check that decryption is still the same as the initial value
        let decrypted_addition = ElGamal::decrypt(&re_encrypted_addition, &sk);
        assert_eq!(decrypted_addition, five);
    }

    #[test]
    fn it_should_show_that_both_re_encryptions_are_equal() {
        let (params, sk, pk) = Helper::setup_md_system();

        let q = params.q();
        let five = BigUint::from(5u32);

        // use a random number < q
        let r = Random::get_random_less_than(&q);
        let encrypted_five = ElGamal::encrypt_encode(&five, &r, &pk);

        // option one: homomorphic addition with zero: 5 + 0 = 5
        let r_ = Random::get_random_less_than(&q);
        let re_encrypted_addition = ElGamal::re_encrypt_via_addition(&encrypted_five, &r_, &pk);
        let decrypted_addition = ElGamal::decrypt(&re_encrypted_addition, &sk);
        assert_eq!(decrypted_addition, five);

        // option two: re-encryption
        let re_encrypted_five = ElGamal::re_encrypt(&encrypted_five, &r_, &pk);
        assert_eq!(re_encrypted_addition, re_encrypted_five);

        // check that both variants produce the same re-encryptions, when using the same random!
        let decrypted_re_encryption = ElGamal::decrypt(&re_encrypted_five, &sk);
        assert_eq!(decrypted_re_encryption, five);

        // check that both re-encryptions produce the same decrypted value
        assert_eq!(decrypted_addition, decrypted_re_encryption);
    }

    #[test]
    #[should_panic(expected = "encryptions and randoms need to have the same length!")]
    fn shuffle_vectors_encryptions_randoms_different_size_should_panic() {
        let (_, _, pk) = Helper::setup_md_system();
        let encryptions = vec![];
        let randoms = vec![BigUint::one()];
        let size = 1;
        let permutation = Random::generate_permutation(&size);
        ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk);
    }

    #[test]
    #[should_panic(expected = "encryptions and permutation need to have the same length!")]
    fn shuffle_vectors_encryptions_permutations_different_size_should_panic() {
        let (_, _, pk) = Helper::setup_md_system();
        let encryptions = vec![];
        let randoms = vec![];
        let size = 1;
        let permutation = Random::generate_permutation(&size);
        ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk);
    }

    #[test]
    #[should_panic(expected = "vectors cannot be empty!")]
    fn shuffle_vectors_size_zero_should_panic() {
        let (_, _, pk) = Helper::setup_md_system();
        let encryptions = vec![];
        let randoms = vec![];
        let permutation = vec![];
        ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk);
    }

    #[test]
    fn it_should_shuffle_a_list_of_encrypted_votes() {
        let (params, sk, pk) = Helper::setup_md_system();
        let q = params.q();
        let zero = BigUint::zero();
        let one = BigUint::one();
        let two = BigUint::from(2u32);

        // get three encrypted values: 0, 1, 2
        let encryptions = Random::generate_random_encryptions(&pk, &q);

        // create three random values < q
        let randoms = [
            Random::get_random_less_than(&q),
            Random::get_random_less_than(&q),
            Random::get_random_less_than(&q),
        ];

        // create a permutation of size 3
        let size = encryptions.len();
        let permutation = Random::generate_permutation(&size);

        // shuffle (permute + re-encrypt_encode) the encryptions
        let shuffle = ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk);

        // destructure the array of tuples
        let shuffled_encryptions = shuffle
            .iter()
            .map(|item| item.0.clone())
            .collect::<Vec<Cipher>>();
        let randoms = shuffle
            .iter()
            .map(|item| item.1.clone())
            .collect::<Vec<BigUint>>();
        let permutation = shuffle.iter().map(|item| item.2).collect::<Vec<usize>>();
        assert!(shuffled_encryptions.len() == 3usize);
        assert!(randoms.len() == 3usize);
        assert!(permutation.len() == 3usize);

        // decrypt the shuffled encryptions
        let mut decryptions = Vec::new();

        for entry in shuffled_encryptions {
            // check that entry (permuted & re-encrypted) is not the same as an existing encryption
            assert!(encryptions.iter().all(|value| value.clone() != entry));

            // decrypt the entry
            let decryption = ElGamal::decrypt(&entry, &sk);
            decryptions.push(decryption);
        }

        // check that at least one value is 0, 1, 2
        assert!(decryptions.iter().any(|value| value.clone() == zero));
        assert!(decryptions.iter().any(|value| value.clone() == one));
        assert!(decryptions.iter().any(|value| value.clone() == two));
    }
}
