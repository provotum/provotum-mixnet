# wasm-pkg (with `wasm-pack`)

Rust code compiled to Web Assembly to be able to use it from the browser (Javascript).

## Installation (Workaround)

The currently available release version of `wasm-pack` (v0.9.1) contains an old version of `wasm_opt` from `wasm-bindgen` which in turn fails the wasm optimization during the release build.
To mitigate the problem, build `wasm-pack` from source i.e.

1. clone the github repository: (https://github.com/rustwasm/wasm-pack)[https://github.com/rustwasm/wasm-pack]
2. change the following
   2.1 search in the code for "version_78" and change it to "version_97" (or higher...).
   2.2 search in the code for "version_90" and change it to "version_97" (or higher...).
   2.3 In file: `src/install/mod.rs`, search for `target::x86_64` and change: `Tool::WasmOpt => "x86-linux",` to `Tool::WasmOpt => "x86_64-linux",`.
   2.4 update the chromedriver version in file: `src/test/webdriver/chromedriver.rs` to the most recent.
3. create a new release build: `cargo build --release`
4. copy `./target/release/wasm-pack` to `~/.cargo/bin/`
5. Now, you should be able to build optimized wasm code using wasm-pack

## 🚴 Usage

### 🛠️ Build with `wasm-pack build`

```
wasm-pack build
```

### 🔬 Test with `wasm-pack test`

#### Headless Chrome

```
wasm-pack test --headless --chrome
```

Requires that the same version of chrome and chromedriver are installed.

- ChromeDriver 86.0.4240.22
- Google Chrome 86.0.4240.75

_Note. It makes sense to fix the required version on the target system. For example, on Ubuntu a package can be specified to "hold" i.e. to not update._

#### NodeJS

```
wasm-pack test --node
```

Requires that NodeJS is installed.

### 🎁 Publish to NPM with `wasm-pack publish`

```
wasm-pack publish
```
