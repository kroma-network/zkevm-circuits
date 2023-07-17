# Circuits for zkEVM

In this repository, zkEVM constraints for the [Kroma](https://github.com/kroma-network/kroma) L2 blockchain are defined. This halo2-based zero-knowledge proof can be used to demonstrate misbehavior of Kroma [Validator](https://github.com/kroma-network/kroma/blob/dev/specs/validations.md) during the [Kroma challenge process](https://github.com/kroma-network/kroma/blob/dev/specs/challenge.md). The additional explanations about Kroma network can be found [here](https://github.com/kroma-network/kroma/blob/dev/specs/challenge.md).

Check out the work in progress [specification](https://github.com/kroma-network/zkevm-specs) to learn how it works.

## Test

To run tests, please use: `make test-all`.

## Project Layout

This repository contains several Rust packages that implement the zkevm. The high-level structure of the repository is as follows:

[`bus-mapping`](https://github.com/kroma-network/zkevm-circuits/tree/develop/bus-mapping)

- a crate designed to parse EVM execution traces and manipulate all of the data they provide in order to obtain structured witness inputs for the EVM Proof and the State Proof.

[`circuit-benchmarks`](https://github.com/kroma-network/zkevm-circuits/tree/develop/circuit-benchmarks)

- Measures performance of each circuit based on proving and verifying time and execution trace parsing and generation for each subcircuit

[`eth-types`](https://github.com/kroma-network/zkevm-circuits/tree/develop/eth-types)

- Different types helpful for various components of the zkevm, such as execution trace parsing or circuits

[`external-tracer`](https://github.com/kroma-network/zkevm-circuits/tree/develop/external-tracer)

- Generates traces by connecting to an external tracer

[`gadgets`](https://github.com/kroma-network/zkevm-circuits/tree/develop/gadgets)

- Custom circuits that abstracts away low-level circuit detail.
- [What are gadgets?](https://zcash.github.io/halo2/concepts/gadgets.html)

[`geth-utils`](https://github.com/kroma-network/zkevm-circuits/tree/develop/geth-utils)

- Provides output from latest geth APIs (debug_trace) as test vectors

[`integration-tests`](https://github.com/kroma-network/zkevm-circuits/tree/develop/integration-tests)

- Integration tests for all circuits

[`keccak256`](https://github.com/kroma-network/zkevm-circuits/tree/develop/keccak256)

- Modules for Keccak hash circuit

[`mock`](https://github.com/kroma-network/zkevm-circuits/tree/develop/mock)

- Mock definitions and methods that are used to test circuits or opcodes

[`testool`](https://github.com/kroma-network/zkevm-circuits/tree/develop/testool)

- CLI that provides tools for testing

[`zkevm-circuits`](https://github.com/kroma-network/zkevm-circuits/tree/develop/zkevm-circuits/src)

- Main package that contains all circuit logic

[`zktrie`](https://github.com/kroma-network/zkevm-circuits/tree/develop/zktrie)

- Modules for Merkle Patricia Trie circuit
