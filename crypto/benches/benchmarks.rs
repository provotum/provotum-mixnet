#![no_main]

use criterion::{criterion_group, criterion_main, Criterion};
use crypto::{
    encryption::ElGamal,
    helper::Helper,
    proofs::keygen::KeyGenerationProof,
    types::{Cipher, PublicKey},
};
use num_bigint::BigUint;
use num_traits::One;

fn setup_shuffling(
    nr_of_votes: usize,
    encoded: bool,
    pk: PublicKey,
) -> (Vec<Cipher>, Vec<usize>, Vec<BigUint>, PublicKey) {
    let q = pk.params.q();

    // encryption of three and one
    let three = BigUint::from(3u32);
    let r = BigUint::parse_bytes(b"1234", 10).unwrap();
    let one = BigUint::one();
    let r_ = BigUint::parse_bytes(b"4321", 10).unwrap();
    let enc_three: Cipher;
    let enc_one: Cipher;

    if encoded {
        enc_three = ElGamal::encrypt_encode(&three, &r, &pk);
        enc_one = ElGamal::encrypt_encode(&one, &r_, &pk);
    } else {
        enc_three = ElGamal::encrypt(&three, &r, &pk);
        enc_one = ElGamal::encrypt(&one, &r_, &pk);
    }

    let mut encryptions: Vec<Cipher> = Vec::new();
    let mut randoms: Vec<BigUint> = Vec::new();
    let power = BigUint::parse_bytes(b"ABCDEF123456789ABCDEF123412341241241241124", 16).unwrap();
    let mut permutation: Vec<usize> = Vec::new();

    for i in 0..nr_of_votes {
        permutation.push(i);

        let mut random = BigUint::from(i);
        random *= BigUint::from(i);
        random = random.modpow(&power, &q);
        randoms.push(random);

        if i % 2 == 0 {
            encryptions.push(enc_three.clone());
        } else {
            encryptions.push(enc_one.clone());
        }
    }

    // create a fake permutation
    permutation.reverse();

    assert!(encryptions.len() == randoms.len());
    assert!(encryptions.len() == permutation.len());
    assert!(encryptions.len() == nr_of_votes);
    (encryptions, permutation, randoms, pk)
}

fn bench_elgamal(c: &mut Criterion) {
    // benchmark config
    let mut group = c.benchmark_group("elgamal");

    group.bench_function("encryption_encoded", |b| {
        b.iter_with_setup(
            || {
                let (_, _, pk) = Helper::setup_lg_system();
                let message = BigUint::from(1u32);
                let random =
                    BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                (message, random, pk)
            },
            |(m, r, pk)| ElGamal::encrypt_encode(&m, &r, &pk),
        )
    });

    group.bench_function("decryption_encoded", |b| {
        b.iter_with_setup(
            || {
                let (_, sk, pk) = Helper::setup_lg_system();
                let message = BigUint::from(1u32);
                let random =
                    BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();

                // encrypt the message
                let encrypted_message = ElGamal::encrypt_encode(&message, &random, &pk);
                (encrypted_message, sk)
            },
            |(encrypted_message, sk)| ElGamal::decrypt_decode(&encrypted_message, &sk),
        )
    });

    group.bench_function("encryption", |b| {
        b.iter_with_setup(
            || {
                let (_, _, pk) = Helper::setup_lg_system();
                let message = BigUint::from(1u32);
                let random =
                    BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                (message, random, pk)
            },
            |(m, r, pk)| ElGamal::encrypt(&m, &r, &pk),
        )
    });

    group.bench_function("decryption", |b| {
        b.iter_with_setup(
            || {
                let (_, sk, pk) = Helper::setup_lg_system();
                let message = BigUint::from(1u32);
                let random =
                    BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();

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
                let (params, _, pk) = Helper::setup_lg_system();
                let one = BigUint::one();

                // encrypt the message
                let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                let enc_one = ElGamal::encrypt_encode(&one, &r, &pk);

                // encrypt the message again
                let r_ = BigUint::parse_bytes(b"170141183460469231731687303712342", 10).unwrap();
                let enc_one_ = ElGamal::encrypt_encode(&one, &r_, &pk);

                (enc_one, enc_one_, params.p)
            },
            |(enc_one, enc_one_, p)| ElGamal::add(&enc_one, &enc_one_, &p),
        )
    });

    group.bench_function("re_encryption_encoded", |b| {
        b.iter_with_setup(
            || {
                let (_, _, pk) = Helper::setup_lg_system();
                let one = BigUint::one();

                // encrypt the message
                let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                let encryption = ElGamal::encrypt_encode(&one, &r, &pk);

                // use another random value for the re_encryption
                let r_ = BigUint::parse_bytes(b"170141183460469231731687303712342", 10).unwrap();

                (encryption, r_, pk)
            },
            |(encryption, r_, pk)| ElGamal::re_encrypt(&encryption, &r_, &pk),
        )
    });

    group.bench_function("re_encryption", |b| {
        b.iter_with_setup(
            || {
                let (_, _, pk) = Helper::setup_lg_system();
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
                let (_, _, pk) = Helper::setup_lg_system();
                let one = BigUint::one();

                // encrypt the message
                let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                let encryption = ElGamal::encrypt_encode(&one, &r, &pk);

                // use another random value for the re_encryption
                let r_ = BigUint::parse_bytes(b"170141183460469231731687303712342", 10).unwrap();

                (encryption, r_, pk)
            },
            |(encryption, r_, pk)| ElGamal::re_encrypt_via_addition(&encryption, &r_, &pk),
        )
    });
}

fn bench_proofs(c: &mut Criterion) {
    // benchmark config
    let mut group = c.benchmark_group("proofs");

    group.bench_function("keygen proof: generate proof", |b| {
        b.iter_with_setup(
            || {
                let sealer_id = "Bob".as_bytes();
                let (params, sk, pk) = Helper::setup_lg_system();
                let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                (params, sk.x, pk.h, r, sealer_id)
            },
            |(params, x, h, r, sealer_id)| {
                KeyGenerationProof::generate(&params, &x, &h, &r, sealer_id)
            },
        )
    });

    group.bench_function("keygen proof: verify proof", |b| {
        b.iter_with_setup(
            || {
                let sealer_id = "Bob".as_bytes();
                let (params, sk, pk) = Helper::setup_lg_system();
                let r = BigUint::parse_bytes(b"170141183460469231731687303715884", 10).unwrap();
                let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, sealer_id);
                (params, pk.h, proof, sealer_id)
            },
            |(params, h, proof, sealer_id)| {
                KeyGenerationProof::verify(&params, &h, &proof, sealer_id)
            },
        )
    });
}

fn bench_shuffle(c: &mut Criterion) {
    let (_, _, pk1) = Helper::setup_256bit_system();
    let (_, _, pk2) = Helper::setup_512bit_system();
    let (_, _, pk3) = Helper::setup_md_system();
    let (_, _, pk4) = Helper::setup_lg_system();
    let (_, _, pk5) = Helper::setup_xl_system();
    let setups = vec![
        (pk1, "shuffling 256bit"),
        (pk2, "shuffling 512bit"),
        (pk3, "shuffling 1024bit"),
        (pk4, "shuffling 2048bit"),
        (pk5, "shuffling 3072bit"),
    ];

    for (pk, name) in setups {
        // benchmark config
        let mut group = c.benchmark_group(name);
        group.sample_size(10);

        group.bench_function("3 votes", |b| {
            b.iter_with_setup(
                || setup_shuffling(3, false, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("10 votes", |b| {
            b.iter_with_setup(
                || setup_shuffling(10, false, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("30 votes", |b| {
            b.iter_with_setup(
                || setup_shuffling(30, false, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("100 votes", |b| {
            b.iter_with_setup(
                || setup_shuffling(100, false, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("1000 votes", |b| {
            b.iter_with_setup(
                || setup_shuffling(1000, false, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("3 votes (encoded)", |b| {
            b.iter_with_setup(
                || setup_shuffling(3, true, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("10 votes (encoded)", |b| {
            b.iter_with_setup(
                || setup_shuffling(10, true, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("30 votes (encoded)", |b| {
            b.iter_with_setup(
                || setup_shuffling(30, true, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("100 votes (encoded)", |b| {
            b.iter_with_setup(
                || setup_shuffling(100, true, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.bench_function("1000 votes (encoded)", |b| {
            b.iter_with_setup(
                || setup_shuffling(1000, true, pk.clone()),
                |(encryptions, permutation, randoms, pk)| {
                    ElGamal::shuffle(&encryptions, &permutation, &randoms, &pk)
                },
            )
        });

        group.finish();
    }
}

criterion_group!(benches, bench_elgamal, bench_proofs, bench_shuffle);
criterion_main!(benches);
