#!/bin/bash

########################################
# relative directories
########################################
readonly name=$(basename $0)
readonly dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly parentDir="$(dirname "$dir")"
readonly parentParentDir="$(dirname "$parentDir")"
readonly projectDir="$(dirname "$parentParentDir")"

########################################
# default mode
########################################
mode=release
insert_keys=false

########################################
# help function definition
########################################
function help {
  cat << EOM
The following parameters are supported:
--insert-keys     starts up the node, inserts the keys and shuts the node down.
--debug           starts the debug build of the substrate node.
--bootnode=[id]   (required, when connecting) the identity of the peer node (bootnode)
EOM
}

# idiomatic parameter and option handling in sh
while test $# -gt 0
do
    case "$1" in
        # insert keys into network or not
        (--insert-keys) 
            insert_keys=true && echo "keys will be inserted.";;
        (--debug)
            mode=debug && echo "debug mode.";;
        # extract the argument after the = sign
        (--bootnode=*)
            bootnode_ip=`(echo $1 | cut -d'=' -f 2)`;;
        (--help)
            help && exit 0;;
    esac
    shift
done

if [[ -z ${bootnode_ip} ]]; then
  echo "Please provide the Peer ID of Node-ZH!"
  exit 0
fi

$projectDir/target/$mode/node-template \
  --chain $projectDir/customLocalChainSpecRaw.json \
  --validator \
  --port 30334 \
  --ws-port 9945 \
  --rpc-port 9934 \
  --name Node-AG \
  --base-path /tmp/node-ag \
  --rpc-methods=Unsafe \
  --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/$bootnode_ip &

process_pid=$!

if [[ "$insert_keys" = true ]]; then
  # wait until the node is ready to answer rpc calls
  sleep 5;

  # insert the aura key
  curl -X POST http://localhost:9934 -H "Content-Type:application/json;charset=utf-8" --data '{"jsonrpc": "2.0", "id": 1, "method": "author_insertKey", "params": ["aura", "paper next author index wedding frost voice mention fetch waste march tilt", "0x74cca68a32156615a5923c67024db70da5e7ed36e70c8cd5bcf3556df152bb6d"]}'

  # insert the grandpa key
  curl -X POST http://localhost:9934 -H "Content-Type:application/json;charset=utf-8" --data '{"jsonrpc": "2.0", "id": 1, "method": "author_insertKey", "params": ["gran", "paper next author index wedding frost voice mention fetch waste march tilt", "0x0fe9065f6450c5501df3efa6b13958949cb4b81a2147d68c14ad25366be1ccb4"]}'
  kill $process_pid
else
  echo "The PID: $process_pid!"
fi  