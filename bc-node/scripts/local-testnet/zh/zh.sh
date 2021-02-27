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
        (--help)
            help && exit 0;;
    esac
    shift
done

# start the node
$projectDir/target/$mode/provotum \
  --chain $projectDir/customLocalChainSpecRaw.json \
  --validator \
  --port 30333 \
  --ws-port 9944 \
  --rpc-port 9933 \
  --name Node-ZH \
  --base-path /tmp/node-zh \
  --execution Native \
  --rpc-methods=Unsafe &

process_pid=$!

if [[ "$insert_keys" = true ]]; then
  # wait until the node is ready to answer rpc calls
  sleep 5;

  # insert the aura key
  curl -X POST http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" --data '{"jsonrpc": "2.0", "id": 1, "method": "author_insertKey", "params": ["aura", "clip organ olive upper oak void inject side suit toilet stick narrow", "0x9effc1668ca381c242885516ec9fa2b19c67b6684c02a8a3237b6862e5c8cd7e"]}'

  # insert the grandpa key
  curl -X POST http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" --data '{"jsonrpc": "2.0", "id": 1, "method": "author_insertKey", "params": ["gran", "clip organ olive upper oak void inject side suit toilet stick narrow", "0xb48004c6e1625282313b07d1c9950935e86894a2e4f21fb1ffee9854d180c781"]}'

  kill $process_pid
else
  echo "The PID: $process_pid!"
fi 
