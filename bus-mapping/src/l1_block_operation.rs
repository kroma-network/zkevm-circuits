//! L1 Block Operation

use core::{cmp::Ordering, fmt};
use eth_types::Word;

use crate::operation::{Op, OpEnum};

/// Represents a field parameter of the L1Block that can be accessed via EVM
/// execution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum L1BlockField {
    /// L1 base fee.
    L1BaseFee,
    /// L1 fee overhead.
    L1FeeOverhead,
    /// L1 fee scalar.
    L1FeeScalar,
    /// Validator Reward Ratio
    ValidatorRewardRatio,
}

/// Represents L1Block read/write operation.
#[derive(Clone, PartialEq, Eq)]
pub struct L1BlockOp {
    /// field of L1Block
    pub field: L1BlockField,
    /// value of L1Block
    pub value: Word,
}

impl fmt::Debug for L1BlockOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("L1BlockOp { ")?;
        f.write_fmt(format_args!(
            "field: {:?}, value: {:?}",
            self.field, self.value,
        ))?;
        f.write_str(" }")
    }
}

impl PartialOrd for L1BlockOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for L1BlockOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.field).cmp(&(&other.field))
    }
}

impl Op for L1BlockOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::L1Block(self)
    }

    fn reverse(&self) -> Self {
        unreachable!("L1BlockOp can't be reverted")
    }
}
