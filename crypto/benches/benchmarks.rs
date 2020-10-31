use criterion::{criterion_group, criterion_main, Criterion};
use crypto::elgamal::{encryption::ElGamal, helper::Helper};
use num_bigint::BigUint;

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

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
