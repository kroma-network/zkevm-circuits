//! The bytecode circuit implementation.

/// byte code circuit
pub mod bytecode_to_hashblock_unroller;
pub use bytecode_to_hashblock_unroller as bytecode_unroller;
/// Bytecode circuit tester
pub mod dev;
pub(crate) mod param;
