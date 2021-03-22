# Provotum Mixnet

The project is structured into four different packages:

- `node`: The Provotum Mixnet implemented using Substrate
- `crypto`: A cryptographic library implementing all algorithms and proofs
- `randomizer`: A service to randomizes the voters ballots'
- `client`: A CLI to interact with the randomizer and the node

For more information have a look at the individual packages.

## Demo Setup

### Start Up

To start a multi-node local test network, the `docker-compose.yml` file can be used.

```bash
docker-compose up
```

This starts a three-node local test network with:

- **Alice**, as voting-authority (cannot author blocks, but is the voting admin)
- **Bob** and **Charlie**, as sealers and PoA-authorities (can author blocks)

Also, starts a randomizer service for ballot re-encryption:

- **Randomizer**

### Interact

To interact with the test setup use the `client` CLI.
Have a look at the **README** of the `client` package on how to build the CLI and use it.
