# crypto (elgamal)

## Testing

To show print statements during test execution use the following command: 

```bash
cargo +nightly test --target wasm32-unknown-unknown -- --nocapture
```

*Note: `--target wasm32-unknown-unknown` always needs to be passed since the crate needs to work as a substrate pallet (wasm).*