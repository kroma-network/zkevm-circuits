//! Params for Kroma Network

use ethers_core::types::Address;
use lazy_static::lazy_static;

use crate::{address, Word};

lazy_static! {
  /// The pre-deployed contract that stores the information to compute l1 rollup cost.
  pub static ref L1_BLOCK: Address = address!("0x4200000000000000000000000000000000000015");
  /// The pre-deployed contract that accumulates base fee.
  pub static ref BASE_FEE_RECIPIENT: Address = address!("0x4200000000000000000000000000000000000019");
  /// The pre-deployed contract that accumulates l1 rollup cost.
  pub static ref L1_FEE_RECIPIENT: Address = address!("0x420000000000000000000000000000000000001A");

  /// The slot for basefee at L1Block.sol.
  pub static ref BASE_FEE_KEY: Word = Word::from(1);
  /// The slot for l1FeeOverhead at L1Block.sol.
  pub static ref L1_FEE_OVERHEAD_KEY: Word = Word::from(5);
  /// The slot or l1FeeScalar at L1Block.sol.
  pub static ref L1_FEE_SCALAR_KEY: Word = Word::from(6);

  /// The denominator used to compute l1 rollup cost.
  pub static ref L1_COST_DENOMINATOR: Word = Word::from(1_000_000);
}
