# Provotum Mix-Net

A mix-net implementation for Substrate.

## Demo Setup

To start a multi-node local test network, the `docker-compose.yml` file can be used.

```bash
docker-compose up
```

This starts a three-node local test network with:

- **Alice**, as voting-authority (cannot author blocks, but is the voting admin)
- **Bob** and **Charlie**, as sealers and PoA-authorities (can author blocks)

Also, starts a randomizer service for ballot re-encryption:

- **Randomizer**
