//! Utility functions to help calculate gas

use super::GasCost;
#[cfg(feature = "kroma")]
use crate::geth_types::DEPOSIT_TX_TYPE;
use crate::Word;

/// Calculate memory expansion gas cost by current and next memory word size.
pub fn memory_expansion_gas_cost(curr_memory_word_size: u64, next_memory_word_size: u64) -> u64 {
    if next_memory_word_size == curr_memory_word_size {
        0
    } else {
        GasCost::MEMORY_EXPANSION_LINEAR_COEFF.0 * (next_memory_word_size - curr_memory_word_size)
            + next_memory_word_size * next_memory_word_size
                / GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR.0
            - curr_memory_word_size * curr_memory_word_size
                / GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR.0
    }
}

/// Calculate memory copier gas cost by current and next memory word size, and
/// number of bytes to copy.
pub fn memory_copier_gas_cost(
    curr_memory_word_size: u64,
    next_memory_word_size: u64,
    num_copy_bytes: u64,
    per_word_copy_gas: u64,
) -> u64 {
    let num_words = (num_copy_bytes + 31) / 32;
    num_words * per_word_copy_gas +
        // Note that opcodes with a byte size parameter of 0 will not trigger
        // memory expansion, regardless of their offset parameters.
        if num_words > 0 {
            memory_expansion_gas_cost(curr_memory_word_size, next_memory_word_size)
        } else {
            0
        }
}

/// Calculate EIP 150 gas passed to callee.
pub fn eip150_gas(gas_left: u64, gas_specified: Word) -> u64 {
    let capped_gas = gas_left - gas_left / 64;

    if gas_specified.bits() <= 64 {
        let gas_specified = gas_specified.low_u64();
        if gas_specified < capped_gas {
            return gas_specified;
        }
    }

    capped_gas
}

/// Calculate used gas during state transition.
/// Normally, it's equivalent to the normal tx's.
/// But for deposit tx, it needs to be computed differently.
pub fn gas_used(_transaction_type: u64, gas: u64, gas_left: u64) -> u64 {
    #[cfg(feature = "kroma")]
    if _transaction_type == DEPOSIT_TX_TYPE {
        gas
    } else {
        gas - gas_left
    }
    #[cfg(not(feature = "kroma"))]
    return gas - gas_left;
}
