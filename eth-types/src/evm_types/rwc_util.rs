//! Utility functions to help calculate rwc

#[cfg(feature = "kroma")]
use crate::geth_types::DEPOSIT_TX_TYPE;

#[cfg(feature = "kroma")]
/// TxId RWC offset in Stop opcode.
pub const STOP_TX_ID_RWC_OFFSET: usize = 1;

#[cfg(feature = "kroma")]
/// RWC offset to be subtracted in EndTx on handling Kroma deposit tx.
/// This contains followings:
///   - Read TxRefund
///   - Write Account Balance
///   - Write Account Balance
pub const END_TX_NOT_USED_RWC_IF_DEPOSIT: usize = 3;

/// RWC offset used by EndTx or EndDepositTx.
pub fn end_tx_rwc(_transaction_type: u64, is_first: bool) -> usize {
    #[cfg(feature = "kroma")]
    if _transaction_type == DEPOSIT_TX_TYPE && !is_first {
        return 9 - END_TX_NOT_USED_RWC_IF_DEPOSIT;
    }
    return 9 - if is_first { 1 } else { 0 };
}
