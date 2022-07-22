//! Common utility traits and functions.
use eth_types::Field;

pub use gadgets::util::Expr;

pub(crate) fn random_linear_combine_word<F: Field>(bytes: [u8; 32], randomness: F) -> F {
    crate::evm_circuit::util::Word::random_linear_combine(bytes, randomness)
}

// the magic number is `echo 'zkevm-circuits' | hexdump`
pub(crate) const DEFAULT_RAND: u128 = 0x10000; //0x6b7a76652d6d6963637269757374u128;
