# crypto (elgamal)

## Build

To create a release build of the crate run the following command.

```bash
cargo +nightly build --verbose --release --target wasm32-unknown-unknown
```

_Note: `--target wasm32-unknown-unknown` always needs to be passed since the crate needs to work as a substrate pallet (wasm)._

## Testing

To test a release build of the crate run the following command.

```bash
cargo +nightly test --verbose --release
```

_Note: Don't pass `--target wasm32-unknown-unknown` since the tests module are allowed to use **std**._

### Show Print Statements

To show print statements during test execution use the following command:

```bash
cargo +nightly test -- --nocapture
```

## Benchmarks

To benchmark a release build of the crate run the following command.

```bash
cargo +nightly bench --features bench
```
