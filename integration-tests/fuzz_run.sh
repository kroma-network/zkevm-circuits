#!/bin/bash

if [ $# -lt 1 ]; then
    echo $0: usage: fuzz_run.sh directory
    exit 1
fi

DIRECTORY=$1
if [[ ! -d "$DIRECTORY" ]]
then
    echo "$DIRECTORY does not exists on your filesystem or it is not a directory."
    exit 1
fi

for testcase in $(ls $DIRECTORY); do
    path=$DIRECTORY/$testcase
    for phase in evm state tx bytecode copy; do
        echo "cargo run --bin test_fuzz $path $phase"
        RUSTFLAGS=-Awarnings cargo run --bin test_fuzz $path $phase
    done
done
