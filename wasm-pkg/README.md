# wasm-pkg

Rust code compiled to Web Assembly to be able to use it from the browser (Javascript).

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
