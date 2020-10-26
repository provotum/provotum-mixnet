use criterion::{criterion_group, criterion_main, Criterion};
use crypto::elgamal::{
    encryption::ElGamal,
    system::{ElGamalParams, Helper},
};
use num_bigint::BigUint;

fn criterion_benchmark(c: &mut Criterion) {
    // benchmark congig
    let mut group = c.benchmark_group("encryption/decryption");
    group.sample_size(500);

    group.bench_function("encrypt", |b| {
        b.iter_with_setup(
            || {
                let params = ElGamalParams {
                    p: BigUint::from(23 as u32),
                    // and, therefore, q -> 11
                    g: BigUint::from(2 as u32),
                };

                // generate a public/private key pair
                let r = BigUint::from(9 as u32);
                let (pk, _sk) = Helper::generate_key_pair(&params, &r);

                // the value of the message: 2
                let message = BigUint::from(2 as u32);

                // a new random value for the encryption
                let r_ = BigUint::from(5 as u32);
                (message, r_, pk)
            },
            |(m, r, pk)| ElGamal::encrypt(&m, &r, &pk),
        )
    });

    group.bench_function("decrypt", |b| {
        b.iter_with_setup(
            || {
                let params = ElGamalParams {
                    p: BigUint::from(23 as u32),
                    // and, therefore, q -> 11
                    g: BigUint::from(2 as u32),
                };

                // generate a public/private key pair
                let r = BigUint::from(9 as u32);
                let (pk, sk) = Helper::generate_key_pair(&params, &r);

                // the value of the message: 2
                let message = BigUint::from(2 as u32);

                // a new random value for the encryption
                let r_ = BigUint::from(5 as u32);

                // encrypt the message
                let encrypted_message = ElGamal::encrypt(&message, &r_, &pk);
                (encrypted_message, sk)
            },
            |(encrypted_message, sk)| ElGamal::decrypt(&encrypted_message, &sk),
        )
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
