# Randomizer

Service responsible to randomize ballots of voters.

- re-encrypts ballots
- creates re-encryption proof

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

The command needs to be execute from the parent folder of: `/randomizer` and `/crypto` (in this case called: `provotum-mixnet`) since both folders are required inside the Docker context during the build.

```bash
~/.../provotum-mixnet: DOCKER_BUILDKIT=1 docker build -f ./randomizer/Dockerfile --tag provotum-randomizer-dev .
```

#### Build Image (Github Action)

A Github Action workflow exists to build the `provotum-randomizer` docker container and push it to the Github container registry. Have a look at the `.github/workflows/build.yml` for more details.

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
