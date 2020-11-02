use criterion::{criterion_group, criterion_main, Criterion};
use crypto::elgamal::{encryption::ElGamal, helper::Helper, random::Random};
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn criterion_benchmark(c: &mut Criterion) {
    // benchmark congig
    let mut group = c.benchmark_group("elgamal");
    group.sample_size(500);

    group.bench_function("encryption", |b| {
        b.iter_with_setup(
            || {
                let (_, _, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
                b"2", 
                b"1701411834604692317316873037");
                let message = BigUint::from(1u32);
                let random = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                (message, random, pk)
            },
            |(m, r, pk)| ElGamal::encrypt(&m, &r, &pk),
        )
    });

    group.bench_function("decryption", |b| {
        b.iter_with_setup(
            || {
                let (_, sk, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
                b"2", 
                b"1701411834604692317316873037");
                let message = BigUint::from(1u32);
                let random = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();

                // encrypt the message
                let encrypted_message = ElGamal::encrypt(&message, &random, &pk);
                (encrypted_message, sk)
            },
            |(encrypted_message, sk)| ElGamal::decrypt(&encrypted_message, &sk),
        )
    });

    group.bench_function("homomorphic addition", |b| {
        b.iter_with_setup(
            || {
                let (params, _, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
                b"2", 
                b"1701411834604692317316873037");
                let one = BigUint::one();
                
                // encrypt the message
                let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                let enc_one = ElGamal::encrypt(&one, &r, &pk);

                // encrypt the message again
                let r_ = BigUint::parse_bytes(b"170141183460469231731687303712342", 10).unwrap();
                let enc_one_ =ElGamal::encrypt(&one, &r_, &pk);

                (enc_one, enc_one_, params.p)
            },
            |(enc_one, enc_one_, p)| ElGamal::add(&enc_one, &enc_one_, &p),
        )
    });

    group.bench_function("re_encryption", |b| {
        b.iter_with_setup(
            || {
                let (_, _, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
                b"2", 
                b"1701411834604692317316873037");
                let one = BigUint::one();
                
                // encrypt the message
                let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                let encryption = ElGamal::encrypt(&one, &r, &pk);

                // use another random value for the re_encryption
                let r_ = BigUint::parse_bytes(b"170141183460469231731687303712342", 10).unwrap();

                (encryption, r_, pk)
            },
            |(encryption, r_, pk)| ElGamal::re_encrypt(&encryption, &r_, &pk),
        )
    });

    group.bench_function("re_encryption by homomorphic addition zero (g^0)", |b| {
        b.iter_with_setup(
            || {
                let (_, _, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
                b"2", 
                b"1701411834604692317316873037");
                let one = BigUint::one();
                
                // encrypt the message
                let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                let encryption = ElGamal::encrypt(&one, &r, &pk);

                // use another random value for the re_encryption
                let r_ = BigUint::parse_bytes(b"170141183460469231731687303712342", 10).unwrap();

                (encryption, r_, pk)
            },
            |(encryption, r_, pk)| ElGamal::re_encrypt_via_addition(&encryption, &r_, &pk),
        )
    });

    group.bench_function("shuffling (permutation + re-encryption)", |b| {
        b.iter_with_setup(
            || {
                let (params, _, pk) = Helper::setup_system(b"85053461164796801949539541639542805770666392330682673302530819774105141531698707146930307290253537320447270457", 
                b"2", 
                b"1701411834604692317316873037");
                let q = params.q();

                // encryption of zero
                let zero = BigUint::zero();
                let r = Random::random_lt_number(&q);
                let enc_zero = ElGamal::encrypt(&zero, &r, &pk);
        
                // encryption of one
                let one = BigUint::one();
                let r_ = Random::random_lt_number(&q);
                let enc_one = ElGamal::encrypt(&one, &r_, &pk);
        
                // encryption of two
                let two = BigUint::from(2u32);
                let r__ = Random::random_lt_number(&q);
                let enc_two = ElGamal::encrypt(&two, &r__, &pk);
        
                let encryptions = vec![enc_zero, enc_one, enc_two];
        
                // create three random values < q
                let randoms = vec![
                    Random::random_lt_number(&q),
                    Random::random_lt_number(&q),
                    Random::random_lt_number(&q),
                ];

                (encryptions, randoms, pk)
            },
            |(encryptions, randoms, pk)| ElGamal::shuffle(&encryptions, &randoms, &pk),
        )
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
