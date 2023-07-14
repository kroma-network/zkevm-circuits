//! mpt-zktrie circuits and utils
//
#![deny(missing_docs)]

pub use mpt_circuits::{
    hash, operation, serde, CommitmentIndexs, EthTrie, EthTrieCircuit, EthTrieConfig, MPTProofType,
};

/// the state modules include structures represent zktrie and witness generator
pub mod state;
