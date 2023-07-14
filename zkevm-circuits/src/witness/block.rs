use super::{
    mpt::ZktrieState as MptState, step::step_convert, tx::tx_convert, Bytecode, ExecStep,
    MptUpdates, RwMap, Transaction,
};
#[cfg(any(feature = "test", test))]
use crate::evm_circuit::{detect_fixed_table_tags, EvmCircuit};
#[cfg(feature = "test")]
use crate::tx_circuit::TX_LEN;
use crate::{
    evm_circuit::util::rlc,
    table::BlockContextFieldTag,
    util::{Challenges, DEFAULT_RAND},
};
use bus_mapping::{
    circuit_input_builder::{self, CircuitsParams, CopyEvent, ExpEvent, TxL1Fee},
    Error,
};
use eth_types::{Address, Field, ToLittleEndian, ToScalar, ToWord, Word, U256};
use ethers_core::types::Signature;
use halo2_proofs::circuit::Value;
use std::collections::{BTreeMap, HashMap};

/// max range of prev blocks allowed inside BLOCKHASH opcode
#[cfg(any(feature = "scroll", feature = "kroma"))]
pub const NUM_PREV_BLOCK_ALLOWED: u64 = 1;
/// max range of prev blocks allowed inside BLOCKHASH opcode
#[cfg(all(not(feature = "kroma"), not(feature = "scroll")))]
pub const NUM_PREV_BLOCK_ALLOWED: u64 = 256;

// TODO: Remove fields that are duplicated in`eth_block`
/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct Block<F> {
    /// The randomness for random linear combination
    pub randomness: F,
    /// Transactions in the block
    pub txs: Vec<Transaction>,
    /// Signatures in the block
    pub sigs: Vec<Signature>,
    /// EndBlock step that is repeated after the last transaction and before
    /// reaching the last EVM row.
    pub end_block_not_last: ExecStep,
    /// Last EndBlock step that appears in the last EVM row.
    pub end_block_last: ExecStep,
    /// Read write events in the RwTable
    pub rws: RwMap,
    /// Bytecode used in the block
    pub bytecodes: HashMap<Word, Bytecode>,
    /// The block context
    pub context: BlockContexts,
    /// The init state of mpt
    pub mpt_state: Option<MptState>,
    /// Copy events for the copy circuit's table.
    pub copy_events: Vec<CopyEvent>,
    /// Exponentiation traces for the exponentiation circuit's table.
    pub exp_events: Vec<ExpEvent>,
    /// Pad exponentiation circuit to make selectors fixed.
    pub exp_circuit_pad_to: usize,
    /// Circuit Setup Parameters
    pub circuits_params: CircuitsParams,
    /// Inputs to the SHA3 opcode
    pub sha3_inputs: Vec<Vec<u8>>,
    /// State root of the previous block
    pub prev_state_root: Word, // TODO: Make this H256
    /// Keccak inputs
    pub keccak_inputs: Vec<Vec<u8>>,
    /// Mpt updates
    pub mpt_updates: MptUpdates,
    /// Chain ID
    pub chain_id: Word,

    /// Kroma
    #[cfg(feature = "kroma")]
    /// L1 fee
    pub l1_fee: TxL1Fee,
    #[cfg(feature = "kroma")]
    /// L1 fee committed
    pub l1_fee_committed: TxL1Fee,
}

/// ...
#[derive(Debug, Default, Clone)]
pub struct BlockContexts {
    /// Hashmap that maps block number to its block context.
    pub ctxs: BTreeMap<u64, BlockContext>,
}

impl BlockContexts {
    /// ..
    pub fn first(&self) -> &BlockContext {
        self.ctxs.iter().next().unwrap().1
    }
    /// ..
    pub fn first_or_default(&self) -> BlockContext {
        self.ctxs
            .iter()
            .next()
            .map(|(_k, v)| v.clone())
            .unwrap_or_default()
    }
}

impl<F: Field> Block<F> {
    /// For each tx, for each step, print the rwc at the beginning of the step,
    /// and all the rw operations of the step.
    pub(crate) fn debug_print_txs_steps_rw_ops(&self) {
        for (tx_idx, tx) in self.txs.iter().enumerate() {
            println!("tx {}", tx_idx);
            for step in &tx.steps {
                println!(" step {:?} rwc: {}", step.execution_state, step.rw_counter);
                for rw_ref in &step.rw_indices {
                    println!("  - {:?}", self.rws[*rw_ref]);
                }
            }
        }
    }
}

#[cfg(feature = "test")]
use crate::exp_circuit::OFFSET_INCREMENT;
#[cfg(feature = "test")]
use crate::util::log2_ceil;

#[cfg(feature = "test")]
impl<F: Field> Block<F> {
    /// Obtains the expected Circuit degree needed in order to be able to test
    /// the EvmCircuit with this block without needing to configure the
    /// `ConstraintSystem`.
    pub fn get_test_degree(&self) -> u32 {
        let num_rows_required_for_execution_steps: usize =
            EvmCircuit::<F>::get_num_rows_required(self);
        let num_rows_required_for_rw_table: usize = self.circuits_params.max_rws;
        let num_rows_required_for_fixed_table: usize = detect_fixed_table_tags(self)
            .iter()
            .map(|tag| tag.build::<F>().count())
            .sum();
        let num_rows_required_for_bytecode_table: usize = self
            .bytecodes
            .values()
            .map(|bytecode| bytecode.bytes.len() + 1)
            .sum();
        let num_rows_required_for_copy_table: usize =
            self.copy_events.iter().map(|c| c.bytes.len() * 2).sum();
        let num_rows_required_for_keccak_table: usize = self.keccak_inputs.len();
        let num_rows_required_for_tx_table: usize =
            TX_LEN * self.circuits_params.max_txs + self.circuits_params.max_calldata;
        let num_rows_required_for_exp_table: usize = self
            .exp_events
            .iter()
            .map(|e| e.steps.len() * OFFSET_INCREMENT)
            .sum();

        const NUM_BLINDING_ROWS: usize = 64;

        let rows_needed: usize = itertools::max([
            num_rows_required_for_execution_steps,
            num_rows_required_for_rw_table,
            num_rows_required_for_fixed_table,
            num_rows_required_for_bytecode_table,
            num_rows_required_for_copy_table,
            num_rows_required_for_keccak_table,
            num_rows_required_for_tx_table,
            num_rows_required_for_exp_table,
        ])
        .unwrap();

        let k = log2_ceil(NUM_BLINDING_ROWS + rows_needed);
        log::debug!(
            "num_rows_required_for rw_table={}, fixed_table={}, bytecode_table={}, \
            copy_table={}, keccak_table={}, tx_table={}, exp_table={}",
            num_rows_required_for_rw_table,
            num_rows_required_for_fixed_table,
            num_rows_required_for_bytecode_table,
            num_rows_required_for_copy_table,
            num_rows_required_for_keccak_table,
            num_rows_required_for_tx_table,
            num_rows_required_for_exp_table
        );
        log::debug!("circuit uses k = {}, rows = {}", k, rows_needed);
        k
    }
}

/// Block context for execution
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// The address of the miner for the block
    pub coinbase: Address,
    /// The gas limit of the block
    pub gas_limit: u64,
    /// The number of the block
    pub number: Word,
    /// The timestamp of the block
    pub timestamp: Word,
    /// The difficulty of the block
    pub difficulty: Word,
    /// The base fee, the minimum amount of gas fee for a transaction
    pub base_fee: Word,
    /// The hash of previous blocks
    pub history_hashes: Vec<Word>,
    /// The chain id
    pub chain_id: Word,
    /// Original Block from geth
    pub eth_block: eth_types::Block<eth_types::Transaction>,
}

impl BlockContext {
    /// Assignments for block table
    pub fn table_assignments<F: Field>(
        &self,
        num_txs: usize,
        cum_num_txs: usize,
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 3]> {
        let current_block_number = self.number.to_scalar().unwrap();
        let randomness = challenges.evm_word();
        [
            vec![
                [
                    Value::known(F::from(BlockContextFieldTag::Coinbase as u64)),
                    Value::known(current_block_number),
                    Value::known(self.coinbase.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Timestamp as u64)),
                    Value::known(current_block_number),
                    Value::known(self.timestamp.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Number as u64)),
                    Value::known(current_block_number),
                    Value::known(current_block_number),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Difficulty as u64)),
                    Value::known(current_block_number),
                    randomness.map(|rand| rlc::value(&self.difficulty.to_le_bytes(), rand)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::GasLimit as u64)),
                    Value::known(current_block_number),
                    Value::known(F::from(self.gas_limit)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::BaseFee as u64)),
                    Value::known(current_block_number),
                    randomness
                        .map(|randomness| rlc::value(&self.base_fee.to_le_bytes(), randomness)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::ChainId as u64)),
                    Value::known(current_block_number),
                    randomness.map(|rand| rlc::value(&self.chain_id.to_le_bytes(), rand)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::NumTxs as u64)),
                    Value::known(current_block_number),
                    Value::known(F::from(num_txs as u64)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::CumNumTxs as u64)),
                    Value::known(current_block_number),
                    Value::known(F::from(cum_num_txs as u64)),
                ],
            ],
            self.block_hash_assignments(randomness),
        ]
        .concat()
    }

    fn block_hash_assignments<F: Field>(&self, randomness: Value<F>) -> Vec<[Value<F>; 3]> {
        #[cfg(all(not(feature = "kroma"), not(feature = "scroll")))]
        let history_hashes: &[U256] = &self.history_hashes;
        #[cfg(any(feature = "scroll", feature = "kroma"))]
        let history_hashes: &[U256] = &[self.eth_block.parent_hash.to_word()];

        let len_history = history_hashes.len();

        history_hashes
            .iter()
            .enumerate()
            .map(|(idx, hash)| {
                let block_number = self
                    .number
                    .low_u64()
                    .checked_sub((len_history - idx) as u64)
                    .unwrap_or_default();
                if block_number + 1 == self.number.low_u64() {
                    debug_assert_eq!(self.eth_block.parent_hash.to_word(), hash.into());
                }
                [
                    Value::known(F::from(BlockContextFieldTag::BlockHash as u64)),
                    Value::known(F::from(block_number)),
                    randomness.map(|randomness| rlc::value(&hash.to_le_bytes(), randomness)),
                ]
            })
            .collect()
    }
}

impl From<&circuit_input_builder::Block> for BlockContexts {
    fn from(block: &circuit_input_builder::Block) -> Self {
        Self {
            ctxs: block
                .headers
                .values()
                .map(|block| {
                    (
                        block.number.as_u64(),
                        BlockContext {
                            coinbase: block.coinbase,
                            gas_limit: block.gas_limit,
                            number: block.number,
                            timestamp: block.timestamp,
                            difficulty: block.difficulty,
                            base_fee: block.base_fee,
                            history_hashes: block.history_hashes.clone(),
                            chain_id: block.chain_id,
                            eth_block: block.eth_block.clone(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        }
    }
}

/// Convert a block struct in bus-mapping to a witness block used in circuits
pub fn block_convert<F: Field>(
    block: &circuit_input_builder::Block,
    code_db: &bus_mapping::state_db::CodeDB,
) -> Result<Block<F>, Error> {
    let rws = RwMap::from(&block.container);
    rws.check_value();
    let num_txs = block.txs().len();
    let last_block_num = block
        .headers
        .iter()
        .rev()
        .next()
        .map(|(k, _)| *k)
        .unwrap_or_default();
    let chain_id = block.chain_id();
    rws.check_rw_counter_sanity();
    let end_block_not_last = step_convert(&block.block_steps.end_block_not_last, last_block_num);
    let end_block_last = step_convert(&block.block_steps.end_block_last, last_block_num);
    log::trace!(
        "witness block: end_block_not_last {:?}, end_block_last {:?}",
        end_block_not_last,
        end_block_last
    );
    let max_rws = if block.circuits_params.max_rws == 0 {
        end_block_last.rw_counter + end_block_last.rw_indices.len() + 1
    } else {
        block.circuits_params.max_rws
    };
    Ok(Block {
        randomness: F::from_u128(DEFAULT_RAND),
        context: block.into(),
        mpt_state: None,
        rws: rws.clone(),
        txs: block
            .txs()
            .iter()
            .enumerate()
            .map(|(idx, tx)| {
                let next_block_num = if idx + 1 < num_txs {
                    block.txs()[idx + 1].block_num
                } else {
                    last_block_num + 1
                };
                tx_convert(tx, idx + 1, chain_id.as_u64(), next_block_num)
            })
            .collect(),
        sigs: block.txs().iter().map(|tx| tx.signature).collect(),
        end_block_not_last,
        end_block_last,
        bytecodes: code_db
            .0
            .iter()
            .map(|(code_hash, bytes)| {
                let hash = Word::from_big_endian(code_hash.as_bytes());
                (
                    hash,
                    Bytecode {
                        hash,
                        bytes: bytes.clone(),
                    },
                )
            })
            .collect(),
        copy_events: block.copy_events.clone(),
        exp_events: block.exp_events.clone(),
        sha3_inputs: block.sha3_inputs.clone(),
        circuits_params: CircuitsParams {
            max_rws,
            ..block.circuits_params
        },
        exp_circuit_pad_to: <usize>::default(),
        prev_state_root: block.prev_state_root,
        keccak_inputs: circuit_input_builder::keccak_inputs(block, code_db)?,
        mpt_updates: MptUpdates::from_rws_with_mock_state_roots(
            &rws.table_assignments(),
            block.prev_state_root,
            block.end_state_root(),
        ),
        chain_id,
        #[cfg(feature = "kroma")]
        l1_fee: TxL1Fee {
            base_fee: block.l1_fee.base_fee,
            fee_overhead: block.l1_fee.fee_overhead,
            fee_scalar: block.l1_fee.fee_scalar,
            validator_reward_scalar: block.l1_fee.validator_reward_scalar,
        },
        #[cfg(feature = "kroma")]
        l1_fee_committed: TxL1Fee {
            base_fee: block.l1_fee_committed.base_fee,
            fee_overhead: block.l1_fee_committed.fee_overhead,
            fee_scalar: block.l1_fee_committed.fee_scalar,
            validator_reward_scalar: block.l1_fee_committed.validator_reward_scalar,
        },
        ..Default::default()
    })
}

/// Attach witness block with mpt states
pub fn block_apply_mpt_state<F: Field>(block: &mut Block<F>, mpt_state: MptState) {
    block.mpt_updates.fill_state_roots(&mpt_state);
    block.mpt_state.replace(mpt_state);
}
