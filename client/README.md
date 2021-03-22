# Client

The Provotum CLI to impersonate voters, the voting-authority and sealers.
The project combines all client-side interactions into a single CLI.
The CLI can be used to interact with the Provotum-Mixnet as well as the Randomizer.

## Local Development

Follow these steps to prepare a local development environment :hammer_and_wrench:

### Setup

Install all the required dependencies by running the following commands.

```bash
curl https://sh.rustup.rs -sSf | sh
rustup default stable
rustup update
```

### Build

Run the following command to build the project in release mode.

```bash
cargo +nightly build --release
```

### Tests

Run the following command to execute all tests.

```bash
cargo +nightly test --release
```

## Run

Run the following command to build the package and run in release mode.

```bash
cargo +nightly run --release
```

## Usage

The CLI can be used via `cargo` or directly via the binary.

### Usage via Cargo

The CLI commands can be shown with the following command.

```bash
cargo +nightly run --release
```

For example, a vote can be created using the following command.

```bash
cargo +nightly run --release -- va setup --vote TestVote --question TestQuestion
```

### Usage via Binary

The CLI commands can be shown with the following command.

```bash
./target/release/provotum-cli
```

For example, a vote can be created using the following command.

```bash
./target/release/provotum-cli va setup --vote TestVote --question TestQuestion
```

### Output

The CLI commands can be shown with the following command.

```bash
provotum-cli 1.0
Moritz Eck <moritz.eck@gmail.com>
The Provotum CLI to impersonate voters, the voting-authority and sealers

USAGE:
    provotum-cli <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help      Prints this message or the help of the given subcommand(s)
    sealer    A subcommand for controlling the Sealer
    va        A subcommand for controlling the Voting Authority
    voter     A subcommand for controlling the Voter
```
