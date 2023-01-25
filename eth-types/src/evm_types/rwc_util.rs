//! Utility functions to help calculate rwc

#[cfg(feature = "kanvas")]
use crate::geth_types::DEPOSIT_TX_TYPE;

#[cfg(feature = "kanvas")]
/// TxId RWC offset in Stop opcode.
pub const STOP_TX_ID_RWC_OFFSET: usize = 1;

#[cfg(feature = "kanvas")]
/// RWC offset to be subtracted in EndTx on handling Kanvas deposit tx.
/// This contains followings:
///   - Read TxRefund
///   - Write Account Balance
///   - Write Account Balance
pub const END_TX_NOT_USED_RWC_IF_DEPOSIT: usize = 3;

/// This adds 1 to offset if the rwc is done after tx_id.
pub fn stop_rwc_offset(rwc: usize) -> usize {
    #[cfg(feature = "kanvas")]
    {
        if rwc < STOP_TX_ID_RWC_OFFSET {
            return rwc;
        } else {
            return rwc + 1;
        }
    }
    #[cfg(not(feature = "kanvas"))]
    rwc
}

/// RWC offset used by EndTx or EndDepositTx.
pub fn end_tx_rwc(_transaction_type: u64, is_first: bool) -> usize {
    #[cfg(feature = "kanvas")]
    let rwc_offset = if _transaction_type == DEPOSIT_TX_TYPE {
        END_TX_NOT_USED_RWC_IF_DEPOSIT
    } else {
        0
    } + if is_first { 1 } else { 0 };
    #[cfg(not(feature = "kanvas"))]
    let rwc_offset = if is_first { 1 } else { 0 };
    return 9 - rwc_offset;
}
