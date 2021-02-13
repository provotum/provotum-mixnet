# Substrate Node Template

A new FRAME-based Substrate node, ready for hacking :rocket:

## Local Development

Follow these steps to prepare a local Substrate development environment :hammer_and_wrench:

### Simple Setup

Install all the required dependencies with a single command (be patient, this can take up to 30
minutes).

```bash
curl https://getsubstrate.io -sSf | bash -s -- --fast
```

#### Dependencies

If the command above doesn't work, the dependencies can also be installed manually. 

```bash
sudo apt install -y cmake pkg-config libssl-dev git gcc build-essential git clang libclang-dev
curl https://sh.rustup.rs -sSf | sh
rustup default stable
rustup toolchain install nightly-2021-01-20
rustup target add wasm32-unknown-unknown --toolchain nightly-2021-01-20
rustup update 
```

#### Upgrading Rust Nightly Version

The current rust nightly version is fixed to the nightly build: `nightly-2021-01-20` to ensure that the project always builds and the tests work.
This is especially the case for the GitHub Actions pipelines which otherwise update their rust versions everytime they are triggered.

In order to upgrade the nightly version, the following commands need to be run: 
```bash
rustup check # check if there is a new version
rustup update # updates the rust version
```

### Manual Setup

Find manual setup instructions at the
[Substrate Developer Hub](https://substrate.dev/docs/en/knowledgebase/getting-started/#manual-installation).

### Build

Once the development environment is set up, build the node template. This command will build the
[Wasm](https://substrate.dev/docs/en/knowledgebase/advanced/executor#wasm-execution) and
[native](https://substrate.dev/docs/en/knowledgebase/advanced/executor#native-execution) code:

```bash
WASM_BUILD_TOOLCHAIN=nightly-2021-01-20 cargo build --release
```

### Docker Container

The following section describes how to build the provotum-mixnet docker image and how to use the Github container registry.

### Github Container Registry

To use the images built and hosted on the Github container registry (ghcr.io), you need to be logged in.

Expose a Github personal access token with `package:read` rights and expose it: 
- locally as an ENV variable `export CR_PAT=***`
- as a Github secret such that it can be used inside a Github Action: `${{ secrets.CR_PAT }}`

#### Login (Local)
 
```bash
echo $CR_PAT | docker login ghcr.io -u $GITHUB_USER --password-stdin
```

#### Build Image (Local)

The command needs to be execute from the parent folder of: `/bc-node` and `/crypto` (in this case called: `provotum-mixnet`) since both folders are required inside the Docker context during the build.

```bash
~/.../provotum-mixnet: DOCKER_BUILDKIT=1 docker build . -f ./bc-node/Dockerfile
```

##### Note. 
Once the project has been published and is publicy available. The path requirement for the `crypto` crate inside `bc-node/pallets/mixnet/Cargo.toml` can be replaced with a reference to the Github project in which the `crypto` crate is hosted.

#### Build Image (Github Action)

A Github Action workflow exists to build the `provotum` docker container and push it to the Github container registry. Have a look at the `.github/workflows/build.yml` for more details.

### Tests

Run the following command to execute all tests.

```bash
cargo +nightly-2021-01-20 test
```

Run the following command to execute the test of the `pallet-mixnet` crate:

```bash
cargo +nightly-2021-01-20 test -p pallet-mixnet --features runtime-benchmarks
```

### Benchmarks

Navigate into the folder: `bc-node/node` and run the following command to check that all benchmarks are working correctly. _Note: This executes the tests._

```bash
cargo +nightly-2021-01-20 test -p pallet-mixnet --features runtime-benchmarks
```

Build the provotum node including the benchmark feature by running the following command: 

```bash
cargo +nightly-2021-01-20 build --features runtime-benchmarks
```

**Note:** To produce results that closely resemble the production environment, make sure to use the flag `--release`. Please, be aware that this will increase the compilation time. Also, the binary will end up inside `./target/release` and not `./target/debug`.

Navigate back to the folder: `bc-node`. 
1. To list all existing commands of the `pallet-mixnet` crate run the following command: 

```bash
./target/debug/provotum benchmark --chain dev --pallet "pallet_mixnet" --extrinsic "*" --repeat 0
```

2. To perform all benchmarks run the following command. _Note: The number of times each benchmark is executed can be changed via `--repeat`._ 

```bash
./target/debug/provotum benchmark --chain dev --pallet "pallet_mixnet" --extrinsic "*" --repeat 10
```

## Run

### Single Node Development Chain

Purge any existing dev chain state:

```bash
./target/release/provotum purge-chain --dev
```

Start a dev chain:

```bash
./target/release/provotum --dev
```

Or, start a dev chain with detailed logging:

```bash
RUST_LOG=debug RUST_BACKTRACE=1 ./target/release/provotum -lruntime=debug --dev
```

### Multi-Node Local Testnet

To start a multi-node local test network, the `docker-compose.yml` file can be used.

```bash
docker-compose up
```

This starts a three-node local test network with: 
- **Alice**, as voting-authority (cannot author blocks, but is the voting admin)
- **Bob** and **Charlie**, as sealers and PoA-authorities (can author blocks)

#### Network Modes

There are two possible network modes:
- **bridge** all containers run in a separate docker network (e.g., 172.31.0.0/16, Alice on 172.31.0.2, Bob on 172.31.0.3, and so on...)
- **host** all containers are exposed on the local network (e.g., 127.0.0.1, Alice on 127.0.0.1:9944, Bob on 127.0.0.1:9945, and so on...)

*Note: If you want to `curl` one of the conatiners from the local network and the containers are running in **bridge** mode, it won't work. You need to either execute the `curl` from inside of one of the containers OR alterantively switch to the host network.* 

Switching networks can be done by commenting out the respective network block in the `docker-compose.yml`:
- to activate **host** network mode:
    ```yaml
      alice:
        container_name: alice
        image: ghcr.io/meck93/provotum-mixnet:latest
        command: --chain=local --name Alice --base-path /tmp/alice --port 30333 --ws-port 9944 --rpc-port 9933
        network_mode: host
        # network_mode: bridge
        # ports:
        #   - 9944:9944 # (host_port:container_port)
        #   - 30333:30333
        #   - 9933:9933
    ```
- to activate **bridge** network mode:
    ```yaml
      alice:
        container_name: alice
        image: ghcr.io/meck93/provotum-mixnet:latest
        command: --chain=local --name Alice --base-path /tmp/alice --port 30333 --ws-port 9944 --rpc-port 9933
        # network_mode: host
        network_mode: bridge
        ports: 
          - 9944:9944 # (host_port:container_port)
          - 30333:30333
          - 9933:9933
    ```

## Structure

A Substrate project such as this consists of a number of components that are spread across a few
directories.

### Node

A blockchain node is an application that allows users to participate in a blockchain network.
Substrate-based blockchain nodes expose a number of capabilities:

-   Networking: Substrate nodes use the [`libp2p`](https://libp2p.io/) networking stack to allow the
    nodes in the network to communicate with one another.
-   Consensus: Blockchains must have a way to come to
    [consensus](https://substrate.dev/docs/en/knowledgebase/advanced/consensus) on the state of the
    network. Substrate makes it possible to supply custom consensus engines and also ships with
    several consensus mechanisms that have been built on top of
    [Web3 Foundation research](https://research.web3.foundation/en/latest/polkadot/NPoS/index.html).
-   RPC Server: A remote procedure call (RPC) server is used to interact with Substrate nodes.

There are several files in the `node` directory - take special note of the following:

-   [`chain_spec.rs`](./node/src/chain_spec.rs): A
    [chain specification](https://substrate.dev/docs/en/knowledgebase/integrate/chain-spec) is a
    source code file that defines a Substrate chain's initial (genesis) state. Chain specifications
    are useful for development and testing, and critical when architecting the launch of a
    production chain. Take note of the `development_config` and `testnet_genesis` functions, which
    are used to define the genesis state for the local development chain configuration. These
    functions identify some
    [well-known accounts](https://substrate.dev/docs/en/knowledgebase/integrate/subkey#well-known-keys)
    and use them to configure the blockchain's initial state.
-   [`service.rs`](./node/src/service.rs): This file defines the node implementation. Take note of
    the libraries that this file imports and the names of the functions it invokes. In particular,
    there are references to consensus-related topics, such as the
    [longest chain rule](https://substrate.dev/docs/en/knowledgebase/advanced/consensus#longest-chain-rule),
    the [Aura](https://substrate.dev/docs/en/knowledgebase/advanced/consensus#aura) block authoring
    mechanism and the
    [GRANDPA](https://substrate.dev/docs/en/knowledgebase/advanced/consensus#grandpa) finality
    gadget.

After the node has been [built](#build), refer to the embedded documentation to learn more about the
capabilities and configuration parameters that it exposes:

```shell
./target/release/provotum --help
```

### Runtime

In Substrate, the terms
"[runtime](https://substrate.dev/docs/en/knowledgebase/getting-started/glossary#runtime)" and
"[state transition function](https://substrate.dev/docs/en/knowledgebase/getting-started/glossary#stf-state-transition-function)"
are analogous - they refer to the core logic of the blockchain that is responsible for validating
blocks and executing the state changes they define. The Substrate project in this repository uses
the [FRAME](https://substrate.dev/docs/en/knowledgebase/runtime/frame) framework to construct a
blockchain runtime. FRAME allows runtime developers to declare domain-specific logic in modules
called "pallets". At the heart of FRAME is a helpful
[macro language](https://substrate.dev/docs/en/knowledgebase/runtime/macros) that makes it easy to
create pallets and flexibly compose them to create blockchains that can address
[a variety of needs](https://www.substrate.io/substrate-users/).

Review the [FRAME runtime implementation](./runtime/src/lib.rs) included in this template and note
the following:

-   This file configures several pallets to include in the runtime. Each pallet configuration is
    defined by a code block that begins with `impl $PALLET_NAME::Trait for Runtime`.
-   The pallets are composed into a single runtime by way of the
    [`construct_runtime!`](https://crates.parity.io/frame_support/macro.construct_runtime.html)
    macro, which is part of the core
    [FRAME Support](https://substrate.dev/docs/en/knowledgebase/runtime/frame#support-library)
    library.

### Pallets

The runtime in this project is constructed using many FRAME pallets that ship with the
[core Substrate repository](https://github.com/paritytech/substrate/tree/master/frame) and a
template pallet that is [defined in the `pallets`](./pallets/mixnet/src/lib.rs) directory.

A FRAME pallet is compromised of a number of blockchain primitives:

-   Storage: FRAME defines a rich set of powerful
    [storage abstractions](https://substrate.dev/docs/en/knowledgebase/runtime/storage) that makes
    it easy to use Substrate's efficient key-value database to manage the evolving state of a
    blockchain.
-   Dispatchables: FRAME pallets define special types of functions that can be invoked (dispatched)
    from outside of the runtime in order to update its state.
-   Events: Substrate uses [events](https://substrate.dev/docs/en/knowledgebase/runtime/events) to
    notify users of important changes in the runtime.
-   Errors: When a dispatchable fails, it returns an error.
-   Trait: The `Trait` configuration interface is used to define the types and parameters upon which
    a FRAME pallet depends.