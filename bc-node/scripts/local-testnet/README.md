# Local Test Network
This folder contains scripts to start the various substrate nodes: 
- ZH (validator, sudo) -> bootnode
- AG (validator)

## How to use it?

### Initial Setup
To start the test network (initial setup): 
1. run `./scripts/zh/zh.sh --insert-keys`, to startup the node **zh** for the first time and insert the aura and gradpa keys.
2. do the same step for the other nodes 
(e.g., `./scripts/ag/ag.sh --insert-keys`)

### Existing Setup
To start the test network: 
1. run `./scripts/zh/zh.sh`, to startup the node **zh**.
2. do the same step for the other nodes but provide the peer node identity for the bootnode (i.e. zh): `./scripts/ag/ag.sh --boodenode=[peerNodeIdentity]`

## Notes

It is important to use `--execution Native` otherwise larger extrinsics will not work i.e. cannot be verified and are rejected.