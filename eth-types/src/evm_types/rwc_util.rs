//! Utility functions to help calculate rwc

#[cfg(feature = "kroma")]
use crate::geth_types::DEPOSIT_TX_TYPE;

#[cfg(feature = "kroma")]
/// Mint RWC offset in BeginTx.
pub const BEGIN_TX_MINT_RWC_OFFSET: usize = 4;

#[cfg(feature = "kroma")]
/// RWC offset to be subtracted in EndTx on handling Kroma deposit tx.
/// This contains followings:
///   - Read TxRefund
///   - Write Account Balance
///   - Write Account Balance
pub const END_TX_NOT_USED_RWC_IF_DEPOSIT: usize = 3;

/// See comment in begin_tx.rs for what are contained in BeginTx.
/// This adds 1 to offset if the rwc is done after mint.
pub fn begin_tx_rwc_offset(_transaction_type: u64, rwc: usize) -> usize {
    #[cfg(feature = "kroma")]
    if _transaction_type == DEPOSIT_TX_TYPE {
        if rwc < BEGIN_TX_MINT_RWC_OFFSET {
            return rwc;
        } else {
            return rwc + 1;
        }
    }
    rwc
}

/// RWC offset used by EndTx or EndDepositTx.
pub fn end_tx_rwc(_transaction_type: u64, is_first: bool) -> usize {
    #[cfg(feature = "kroma")]
    if _transaction_type == DEPOSIT_TX_TYPE && !is_first {
        return 9 - END_TX_NOT_USED_RWC_IF_DEPOSIT;
    }
    9 - if is_first { 1 } else { 0 }
}
