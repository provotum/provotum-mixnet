# wasm-pkg (with `wasm-bindgen`)

## 🔬 Test with `wasm-bindgen-test`

1. Install the test runner: `cargo install wasm-bindgen-cli --vers "same version as wasm-bindgen"`

2. Create a file: `./.cargo/config` and add the following code

```toml
[target.wasm32-unknown-unknown]
runner = 'wasm-bindgen-test-runner'
```

### Headless Chrome

```
cargo test --target wasm32-unknown-unknown
```

Requires that the same version of chrome and chromedriver are installed.

- ChromeDriver 86.0.4240.22
- Google Chrome 86.0.4240.75

_Note. It makes sense to fix the required version on the target system. For example, on Ubuntu a package can be specified to "hold" i.e. to not update._

Requires that the chromedriver is available on `$PATH`
