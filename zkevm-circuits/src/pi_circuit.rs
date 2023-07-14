//! Public Input Circuit implementation

use std::{iter, marker::PhantomData};

use crate::table::{BlockContextFieldTag, KeccakTable};
use bus_mapping::circuit_input_builder::get_dummy_tx_hash;
use eth_types::{Address, Field, Hash, ToBigEndian, Word, H256};
use ethers_core::utils::keccak256;
use halo2_proofs::plonk::{Assigned, Expression, Fixed, Instance};
// Address, BigEndianHash, Field, ToBigEndian, ToLittleEndian, ToScalar, Word, H256,

use crate::{
    table::{BlockTable, LookupTable, TxTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
};
#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

#[cfg(feature = "reject-eip2718")]
use crate::tx_circuit::{TX_HASH_OFFSET, TX_LEN};
use crate::{
    evm_circuit::util::constraint_builder::BaseConstraintBuilder,
    state_circuit::StateCircuitExports,
    witness::{self, Block, BlockContext, BlockContexts, Transaction},
};
use bus_mapping::util::read_env_var;
use gadgets::util::{not, select, Expr};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use once_cell::sync::Lazy;

use crate::table::BlockContextFieldTag::{
    BaseFee, BlockHash, ChainId, Coinbase, CumNumTxs, Difficulty, GasLimit, NumTxs, Number,
    Timestamp,
};
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};
use itertools::Itertools;

/// Fixed by the spec
const BLOCK_LEN: usize = 10;
const NUM_HISTORY_HASHES: usize = 1;
const BYTE_POW_BASE: u64 = 256;
const BLOCK_HEADER_BYTES_NUM: usize = 122;
// chain_id || coinbase || difficulty
const BLOCK_HEADER_CONST_BYTES_NUM: usize = 84;
const KECCAK_DIGEST_SIZE: usize = 32;
const RPI_CELL_IDX: usize = 0;
const RPI_RLC_ACC_CELL_IDX: usize = 1;
const ZERO_BYTE_GAS_COST: u64 = 4;
const NONZERO_BYTE_GAS_COST: u64 = 16;

const PARENT_HASH_OFFSET: usize = 9;
const BLOCK_NUM_OFFSET: usize = 2;
const TIMESTAMP_OFFSET: usize = 1;
const BASE_FEE_OFFSET: usize = 5;
const GAS_LIMIT_OFFSET: usize = 4;
const NUM_TXS_OFFSET: usize = 7;
const CUM_NUM_TXS_OFFSET: usize = 8;
const CHAIN_ID_OFFSET: usize = 6;
const COINBASE_OFFSET: usize = 0;
const DIFFICULTY_OFFSET: usize = 3;

pub(crate) static CHAIN_ID: Lazy<Word> = Lazy::new(|| read_env_var("CHAIN_ID", Word::zero()));
pub(crate) static COINBASE: Lazy<Address> = Lazy::new(|| read_env_var("COINBASE", Address::zero()));
pub(crate) static DIFFICULTY: Lazy<Word> = Lazy::new(|| read_env_var("DIFFICULTY", Word::zero()));

/// PublicData contains all the values that the PiCircuit receives as input
#[derive(Debug, Clone)]
pub struct PublicData {
    /// chain id
    pub chain_id: Word,
    /// Block Transactions
    pub transactions: Vec<Transaction>,
    /// Block contexts
    pub block_ctxs: BlockContexts,
    /// Previous State Root
    pub prev_state_root: Hash,
    /// Withdraw Trie Root
    pub withdraw_trie_root: Hash,
}

impl Default for PublicData {
    fn default() -> Self {
        PublicData {
            chain_id: Word::default(),
            transactions: vec![],
            prev_state_root: H256::zero(),
            withdraw_trie_root: H256::zero(),
            block_ctxs: Default::default(),
        }
    }
}

impl PublicData {
    /// Compute the raw_public_inputs bytes from the verifier's perspective.
    fn raw_public_input_bytes(&self, max_txs: usize) -> Vec<u8> {
        let dummy_tx_hash = get_dummy_tx_hash(self.chain_id.as_u64());
        let withdraw_trie_root = self.withdraw_trie_root;

        let result = iter::empty()
            // state roots
            .chain(self.prev_state_root.to_fixed_bytes())
            .chain(
                self.block_ctxs
                    .ctxs
                    .last_key_value()
                    .map(|(_, blk)| blk.eth_block.state_root)
                    .unwrap_or(self.prev_state_root)
                    .to_fixed_bytes(),
            )
            // withdraw trie root
            .chain(withdraw_trie_root.to_fixed_bytes())
            .chain(self.block_ctxs.ctxs.iter().flat_map(|(block_num, block)| {
                let num_txs = self
                    .transactions
                    .iter()
                    .filter(|tx| tx.block_number == *block_num)
                    .count() as u16;
                let parent_hash = block.eth_block.parent_hash;
                log::debug!(
                    "block.history_hashes.len() = {}, parent_hash = {}",
                    block.history_hashes.len(),
                    parent_hash
                );

                iter::empty()
                    // Block Values
                    .chain(
                        block
                            .eth_block
                            .hash
                            .expect("block.eth_block.hash should be some")
                            .to_fixed_bytes(),
                    )
                    .chain(parent_hash.to_fixed_bytes()) // parent hash
                    .chain(block.number.as_u64().to_be_bytes())
                    .chain(block.timestamp.as_u64().to_be_bytes())
                    .chain(block.base_fee.to_be_bytes())
                    .chain(block.gas_limit.to_be_bytes())
                    .chain(num_txs.to_be_bytes())
            }))
            // Tx Hashes
            .chain(
                self.transactions
                    .iter()
                    .flat_map(|tx| tx.hash.to_fixed_bytes()),
            )
            .chain(
                (0..(max_txs - self.transactions.len()))
                    .into_iter()
                    .flat_map(|_| dummy_tx_hash.to_fixed_bytes()),
            )
            .collect::<Vec<u8>>();

        assert_eq!(
            result.len(),
            BLOCK_HEADER_BYTES_NUM * self.block_ctxs.ctxs.len()
                + KECCAK_DIGEST_SIZE * 3
                + KECCAK_DIGEST_SIZE * max_txs
        );
        result
    }

    fn get_pi(&self, max_txs: usize) -> H256 {
        let rpi_bytes = self.raw_public_input_bytes(max_txs);
        let rpi_keccak = keccak256(rpi_bytes);
        H256(rpi_keccak)
    }
}

impl Default for BlockContext {
    fn default() -> Self {
        Self {
            chain_id: *CHAIN_ID,
            coinbase: *COINBASE,
            difficulty: *DIFFICULTY,
            gas_limit: 0,
            number: Default::default(),
            timestamp: Default::default(),
            base_fee: Default::default(),
            history_hashes: vec![],
            eth_block: Default::default(),
        }
    }
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field> {
    /// Max number of supported transactions
    max_txs: usize,
    /// Max number of supported calldata bytes
    max_calldata: usize,
    /// Max number of supported inner blocks in a batch
    max_inner_blocks: usize,

    /// dedicated column to store the chain_id, difficulty, coinbase constants
    constant: Column<Fixed>,

    raw_public_inputs: Column<Advice>, // block, history_hashes, states, tx hashes
    rpi_field_bytes: Column<Advice>,   // rpi in bytes
    rpi_field_bytes_acc: Column<Advice>,
    rpi_rlc_acc: Column<Advice>, // RLC(rpi) as the input to Keccak table
    rpi_length_acc: Column<Advice>,

    is_rpi_padding: Column<Advice>,
    real_rpi: Column<Advice>,

    // columns for assertion about cum_num_txs in block table
    cum_num_txs: Column<Advice>,
    block_tag_bits: BinaryNumberConfig<BlockContextFieldTag, 4>,
    q_block_tag: Column<Fixed>,

    q_field_start: Selector,
    q_field_step: Selector,
    is_field_rlc: Column<Fixed>,
    q_field_end: Selector,

    q_start: Selector,
    q_not_end: Selector,
    q_keccak: Selector,

    pi: Column<Instance>, // hi(keccak(rpi)), lo(keccak(rpi))

    // External tables
    block_table: BlockTable,
    tx_table: TxTable,
    keccak_table: KeccakTable,

    pub(crate) state_roots: Option<StateCircuitExports<Assigned<F>>>,

    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct PiCircuitConfigArgs<F: Field> {
    /// Max number of supported transactions
    pub max_txs: usize,
    /// Max number of supported calldata bytes
    pub max_calldata: usize,
    /// Max number of supported blocks in a batch
    pub max_inner_blocks: usize,
    /// TxTable
    pub tx_table: TxTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// Keccak Table
    pub keccak_table: KeccakTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for PiCircuitConfig<F> {
    type ConfigArgs = PiCircuitConfigArgs<F>;

    /// Return a new PiCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            max_txs,
            max_calldata,
            max_inner_blocks,
            block_table,
            tx_table,
            keccak_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let constant = meta.fixed_column();
        let rpi = meta.advice_column_in(SecondPhase);
        let rpi_bytes = meta.advice_column();
        let rpi_bytes_acc = meta.advice_column_in(SecondPhase);
        let rpi_rlc_acc = meta.advice_column_in(SecondPhase);
        let rpi_length_acc = meta.advice_column();
        let is_rpi_padding = meta.advice_column();
        let real_rpi = meta.advice_column_in(SecondPhase);

        let pi = meta.instance_column();

        // Annotate table columns
        tx_table.annotate_columns(meta);
        block_table.annotate_columns(meta);

        let q_field_start = meta.complex_selector();
        let q_field_step = meta.complex_selector();
        let q_field_end = meta.complex_selector();
        let is_field_rlc = meta.fixed_column();

        let q_start = meta.complex_selector();
        let q_not_end = meta.complex_selector();
        let q_keccak = meta.complex_selector();

        let q_block_tag = meta.fixed_column();
        let cum_num_txs = meta.advice_column();
        let block_tag_bits = BinaryNumberChip::configure(meta, q_block_tag, Some(block_table.tag));

        meta.enable_equality(constant);
        meta.enable_equality(rpi_bytes);
        meta.enable_equality(rpi);
        meta.enable_equality(real_rpi);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(block_table.value); // copy block to rpi
        meta.enable_equality(tx_table.value); // copy tx hashes to rpi
        meta.enable_equality(pi);

        // field bytes
        meta.create_gate(
            "rpi_bytes_acc[i+1] = rpi_bytes_acc[i] * t + rpi_bytes[i+1]",
            |meta| {
                let q_field_step = meta.query_selector(q_field_step);
                let bytes_acc_next = meta.query_advice(rpi_bytes_acc, Rotation::next());
                let bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
                let bytes_next = meta.query_advice(rpi_bytes, Rotation::next());
                let is_field_rlc = meta.query_fixed(is_field_rlc, Rotation::next());
                let evm_rand = challenges.evm_word();
                let t = select::expr(is_field_rlc, evm_rand, BYTE_POW_BASE.expr());

                vec![q_field_step * (bytes_acc_next - (bytes_acc * t + bytes_next))]
            },
        );
        meta.create_gate("rpi_bytes_acc = rpi_bytes for field start", |meta| {
            let q_field_start = meta.query_selector(q_field_start);
            let rpi_field_bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
            let rpi_field_bytes = meta.query_advice(rpi_bytes, Rotation::cur());

            vec![q_field_start * (rpi_field_bytes_acc - rpi_field_bytes)]
        });
        meta.create_gate("rpi_bytes_acc = rpi for field end", |meta| {
            let q_field_end = meta.query_selector(q_field_end);
            let rpi_bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
            let rpi = meta.query_advice(rpi, Rotation::cur());

            vec![q_field_end * (rpi - rpi_bytes_acc)]
        });
        meta.create_gate("rpi_next = rpi", |meta| {
            let q_field_step = meta.query_selector(q_field_step);
            let rpi_next = meta.query_advice(rpi, Rotation::next());
            let rpi = meta.query_advice(rpi, Rotation::cur());

            vec![q_field_step * (rpi_next - rpi)]
        });

        // rpi_rlc
        meta.create_gate(
            "rpi_rlc_acc[i+1] = keccak_rand * rpi_rlc_acc[i] + rpi_bytes[i+1]",
            |meta| {
                // if is_rpi_padding is true, then
                //   q_not_end * row_next.rpi_rlc_acc ==
                //   (q_not_end * row.rpi_rlc_acc * keccak_rand + row_next.rpi_bytes)
                // else,
                //   q_not_end * row_next.rpi_rlc_acc == q_not_end * row.rpi_rlc_acc
                let mut cb = BaseConstraintBuilder::default();
                let is_rpi_padding = meta.query_advice(is_rpi_padding, Rotation::next());
                let rpi_rlc_acc_cur = meta.query_advice(rpi_rlc_acc, Rotation::cur());
                let rpi_bytes_next = meta.query_advice(rpi_bytes, Rotation::next());
                let keccak_rand = challenges.keccak_input();

                cb.require_equal(
                    "rpi_rlc_acc' = is_rpi_padding ? rpi_rlc_acc : rpi_rlc_acc * r + rpi_bytes'",
                    meta.query_advice(rpi_rlc_acc, Rotation::next()),
                    select::expr(
                        is_rpi_padding.expr(),
                        rpi_rlc_acc_cur.expr(),
                        rpi_rlc_acc_cur * keccak_rand + rpi_bytes_next,
                    ),
                );

                cb.require_equal(
                    "rpi_length_acc' = rpi_length_acc + (is_rpi_padding ? 0 : 1)",
                    meta.query_advice(rpi_length_acc, Rotation::next()),
                    meta.query_advice(rpi_length_acc, Rotation::cur())
                        + select::expr(is_rpi_padding, 0.expr(), 1.expr()),
                );

                cb.gate(meta.query_selector(q_not_end))
            },
        );
        meta.create_gate("rpi_rlc_acc[0] = rpi_bytes[0]", |meta| {
            let q_start = meta.query_selector(q_start);
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            let rpi_bytes = meta.query_advice(rpi_bytes, Rotation::cur());

            vec![q_start * (rpi_rlc_acc - rpi_bytes)]
        });
        meta.create_gate("real rpi", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_rpi_padding is boolean",
                meta.query_advice(is_rpi_padding, Rotation::cur()),
            );

            cb.require_equal(
                "real_rpi == not(is_rpi_padding) * rpi",
                meta.query_advice(real_rpi, Rotation::cur()),
                not::expr(meta.query_advice(is_rpi_padding, Rotation::cur()))
                    * meta.query_advice(rpi, Rotation::cur()),
            );

            cb.gate(meta.query_selector(q_not_end))
        });

        meta.lookup_any("keccak(rpi)", |meta| {
            let is_enabled = meta.query_advice(keccak_table.is_enabled, Rotation::cur());
            let input_rlc = meta.query_advice(keccak_table.input_rlc, Rotation::cur());
            let input_len = meta.query_advice(keccak_table.input_len, Rotation::cur());
            let output_rlc = meta.query_advice(keccak_table.output_rlc, Rotation::cur());
            let q_keccak = meta.query_selector(q_keccak);

            let rpi_rlc = meta.query_advice(rpi, Rotation::cur());
            let rpi_length = meta.query_advice(rpi_length_acc, Rotation::cur());
            let output = meta.query_advice(rpi_rlc_acc, Rotation::cur());

            vec![
                (q_keccak.expr() * 1.expr(), is_enabled),
                (q_keccak.expr() * rpi_rlc, input_rlc),
                (
                    q_keccak.expr()
                        // * (BLOCK_HEADER_BYTES_NUM + max_txs * KECCAK_DIGEST_SIZE).expr(),
                        * rpi_length,
                    input_len,
                ),
                (q_keccak * output, output_rlc),
            ]
        });

        // The 32 bytes of keccak output are combined into (hi, lo)
        //  where r = challenges.evm_word().
        // And the layout will be like this.
        // | rpi | rpi_bytes | rpi_bytes_acc | rpi_rlc_acc |
        // | hi  |    b31    |      b31      |     b31     |
        // | hi  |    b30    | b31*2^8 + b30 | b31*r + b30 |
        // | hi  |    ...    |      ...      |     ...     |
        // | hi  |    b16    | b31*2^120+... | b31*r^15+...|
        // | lo  |    b15    |      b15      | b31*r^16+...|
        // | lo  |    b14    | b15*2^8 + b14 | b31*r^17+...|
        // | lo  |    ...    |      ...      |     ...     |
        // | lo  |     b0    | b15*2^120+... | b31*r^31+...|

        meta.create_gate("cum_num_txs == 0 for first row", |meta| {
            let q_start = meta.query_selector(q_start);
            let cum_num_txs = meta.query_advice(cum_num_txs, Rotation::next());

            vec![q_start * cum_num_txs]
        });
        meta.create_gate(
            "cum_num_txs::next == cum_num_txs::cur + (block_table.tag == NumTxs) ? block_table.value : 0",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();
                let q_block_tag = meta.query_fixed(q_block_tag, Rotation::cur());
                let num_txs = meta.query_advice(block_table.value, Rotation::cur());
                let cum_num_txs_cur = meta.query_advice(cum_num_txs, Rotation::cur());
                let cum_num_txs_next = meta.query_advice(cum_num_txs, Rotation::next());
                let is_num_txs_field = block_tag_bits.value_equals(BlockContextFieldTag::NumTxs, Rotation::cur())(meta);
                let block_tag = meta.query_advice(block_table.tag, Rotation::cur());
                let tag_bits = block_tag_bits.value(Rotation::cur())(meta);

                let num_txs = select::expr(
                    is_num_txs_field,
                    num_txs,
                    0.expr(),
                );
                cb.require_equal(
                    "block_tag_bits == block_tag",
                    block_tag,
                    tag_bits,
                );
                cb.require_equal(
                    "cum_num_txs",
                    cum_num_txs_next,
                    cum_num_txs_cur + num_txs,
                );

                cb.gate(q_block_tag)
            }
        );

        Self {
            max_txs,
            max_calldata,
            max_inner_blocks,
            block_table,
            tx_table,
            keccak_table,
            constant,
            raw_public_inputs: rpi,
            rpi_field_bytes: rpi_bytes,
            rpi_field_bytes_acc: rpi_bytes_acc,
            rpi_rlc_acc,
            rpi_length_acc,
            is_rpi_padding,
            real_rpi,
            q_field_start,
            q_field_step,
            is_field_rlc,
            q_field_end,
            q_start,
            q_not_end,
            q_keccak,
            cum_num_txs,
            block_tag_bits,
            q_block_tag,
            pi,
            _marker: PhantomData,
            state_roots: None,
        }
    }
}

impl<F: Field> PiCircuitConfig<F> {
    #[allow(clippy::type_complexity)]
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData,
        block_value_cells: &[AssignedCell<F, F>],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let block_values = &public_data.block_ctxs;
        let tx_hashes = public_data
            .transactions
            .iter()
            .map(|tx| tx.hash)
            .collect::<Vec<H256>>();

        let mut offset = 0;
        let mut rpi_length_acc = 0u64;
        let mut block_copy_cells = vec![];
        let mut tx_copy_cells = vec![];
        let mut block_table_offset = 1; // first row of block is all-zeros.
        let mut rpi_rlc_acc = Value::known(F::zero());
        let dummy_tx_hash = get_dummy_tx_hash(public_data.chain_id.as_u64());

        self.q_start.enable(region, offset)?;

        // assign constants
        let mut pi_constants = vec![];
        pi_constants.extend_from_slice(&CHAIN_ID.to_be_bytes()[..]);
        pi_constants.extend_from_slice(&COINBASE.to_fixed_bytes()[..]);
        pi_constants.extend_from_slice(&DIFFICULTY.to_be_bytes()[..]);

        let pi_constants = pi_constants
            .into_iter()
            .enumerate()
            .map(|(i, byte)| {
                region.assign_fixed(
                    || format!("PI constant {}", i),
                    self.constant,
                    i,
                    || Value::known(F::from(byte as u64)),
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // assign state roots
        // previous_state_root before applying this batch
        let prev_state_cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &public_data.prev_state_root.to_fixed_bytes(),
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            challenges,
            false,
        )?;

        // state_root after applying this batch
        let next_state_root = block_values
            .ctxs
            .last_key_value()
            .map(|(_, blk)| blk.eth_block.state_root)
            .unwrap_or(public_data.prev_state_root);
        log::debug!(
            "assign pi circuit prev_state_root {:?} next_state_root {:?}",
            public_data.prev_state_root,
            next_state_root
        );
        let next_state_cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &next_state_root.to_fixed_bytes(),
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            challenges,
            false,
        )?;

        let withdraw_trie_root = Word::zero();
        self.assign_field_in_pi(
            region,
            &mut offset,
            &withdraw_trie_root.to_be_bytes(),
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            challenges,
            false,
        )?;

        // copy state roots to pi circuit when we are in super circuit.
        if self.state_roots.is_some() {
            log::debug!("connect state roots {:?}", self.state_roots);
            let state_roots = self.state_roots.clone().unwrap();
            region.constrain_equal(
                prev_state_cells[RPI_CELL_IDX].cell(),
                state_roots.start_state_root.0,
            )?;
            region.constrain_equal(
                next_state_cells[RPI_CELL_IDX].cell(),
                state_roots.end_state_root.0,
            )?;
        } else {
            log::warn!("state roots are not set, skip connection with state circuit");
        }

        for (i, block) in block_values
            .ctxs
            .values()
            .cloned()
            .chain(
                (block_values.ctxs.len()..self.max_inner_blocks)
                    .into_iter()
                    .map(|_| BlockContext::default()),
            )
            .enumerate()
        {
            let block_hash = if i < block_values.ctxs.len() {
                block.eth_block.hash.expect("eth_block.hash should be some")
            } else {
                H256::zero()
            };
            let parent_hash = block.eth_block.parent_hash;
            log::debug!(
                "block.history_hashes.len() = {}, parent hash = {}",
                block.history_hashes.len(),
                parent_hash
            );

            let is_rpi_padding = i >= block_values.ctxs.len();
            let num_txs = public_data
                .transactions
                .iter()
                .filter(|tx| tx.block_number == block.number.as_u64())
                .count() as u16;

            // Assign fields in pi columns and connect them to block table
            // block hash
            self.assign_field_in_pi(
                region,
                &mut offset,
                &block_hash.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;

            // parent hash
            let mut cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &parent_hash.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                cells[RPI_CELL_IDX].clone(),
                block_table_offset + PARENT_HASH_OFFSET,
            ));

            // number
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.number.as_u64().to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                cells[RPI_CELL_IDX].clone(),
                block_table_offset + BLOCK_NUM_OFFSET,
            ));

            // timestamp
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.timestamp.as_u64().to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                cells[RPI_CELL_IDX].clone(),
                block_table_offset + TIMESTAMP_OFFSET,
            ));

            // base_fee
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.base_fee.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                cells[RPI_CELL_IDX].clone(),
                block_table_offset + BASE_FEE_OFFSET,
            ));

            // gas_limit
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.gas_limit.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                cells[RPI_CELL_IDX].clone(),
                block_table_offset + GAS_LIMIT_OFFSET,
            ));

            // num_txs
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &num_txs.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                cells[RPI_CELL_IDX].clone(),
                block_table_offset + NUM_TXS_OFFSET,
            ));

            // chain_id
            let chain_id_cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.chain_id.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                false,
                true,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                chain_id_cells[RPI_CELL_IDX].clone(),
                block_table_offset + CHAIN_ID_OFFSET,
            ));
            // coinbase
            let coinbase_cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.coinbase.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                false,
                true,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                coinbase_cells[RPI_CELL_IDX].clone(),
                block_table_offset + COINBASE_OFFSET,
            ));
            // difficulty
            let difficulty_cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.difficulty.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                false,
                true,
                challenges,
                false,
            )?;
            block_copy_cells.push((
                difficulty_cells[RPI_CELL_IDX].clone(),
                block_table_offset + DIFFICULTY_OFFSET,
            ));

            let mut pi_cells = vec![];
            pi_cells.extend_from_slice(&chain_id_cells[2..]);
            pi_cells.extend_from_slice(&coinbase_cells[2..]);
            pi_cells.extend_from_slice(&difficulty_cells[2..]);

            for (_constant, _byte) in pi_constants.iter().zip(pi_cells.into_iter()) {
                // TODO: re-enable chain_id constraints
                // region.constrain_equal(constant.cell(), byte.cell())?;
            }
            block_table_offset += BLOCK_LEN;
        }
        debug_assert_eq!(
            offset,
            32 * 3
                + (BLOCK_HEADER_BYTES_NUM + BLOCK_HEADER_CONST_BYTES_NUM) * self.max_inner_blocks
        );

        // assign tx hashes
        let num_txs = tx_hashes.len();
        let mut rpi_rlc_cell = None;
        for tx_hash in tx_hashes.into_iter().chain(
            (0..self.max_txs - num_txs)
                .into_iter()
                .map(|_| dummy_tx_hash),
        ) {
            let cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &tx_hash.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                false,
                false,
                challenges,
                false,
            )?;
            tx_copy_cells.push(cells[RPI_CELL_IDX].clone());
            rpi_rlc_cell = Some(cells[RPI_RLC_ACC_CELL_IDX].clone());
        }

        debug_assert_eq!(
            offset,
            (BLOCK_HEADER_BYTES_NUM + BLOCK_HEADER_CONST_BYTES_NUM) * self.max_inner_blocks
                + KECCAK_DIGEST_SIZE * 3
                + KECCAK_DIGEST_SIZE * self.max_txs
        );

        for i in 0..(offset - 1) {
            self.q_not_end.enable(region, i)?;
        }

        for (block_cell, row_offset) in block_copy_cells.into_iter() {
            region.constrain_equal(
                block_cell.cell(),
                block_value_cells[row_offset - 1].cell(), /* -1 for block table's first row of
                                                           * all-zeros */
            )?;
        }
        #[cfg(feature = "reject-eip2718")]
        for (i, tx_hash_cell) in tx_copy_cells.into_iter().enumerate() {
            use halo2_proofs::circuit::{Cell, RegionIndex};
            region.constrain_equal(
                tx_hash_cell.cell(),
                Cell {
                    region_index: RegionIndex(1), // FIXME: this is not safe
                    row_offset: i * TX_LEN + TX_HASH_OFFSET,
                    column: self.tx_table.value.into(),
                },
            )?;
        }
        // assign rpi_acc, keccak_rpi
        let keccak_row = offset;
        let rpi_rlc_cell = rpi_rlc_cell.unwrap();
        rpi_rlc_cell.copy_advice(
            || "keccak(rpi)_input",
            region,
            self.raw_public_inputs,
            keccak_row,
        )?;
        let keccak = public_data.get_pi(self.max_txs);
        let keccak_rlc =
            keccak
                .to_fixed_bytes()
                .iter()
                .fold(Value::known(F::zero()), |acc, byte| {
                    acc.zip(challenges.evm_word())
                        .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)))
                });
        region.assign_advice(
            || "rpi_length_acc",
            self.rpi_length_acc,
            keccak_row,
            || Value::known(F::from(rpi_length_acc)),
        )?;
        let keccak_output_cell = region.assign_advice(
            || "keccak(rpi)_output",
            self.rpi_rlc_acc,
            keccak_row,
            || keccak_rlc,
        )?;
        self.q_keccak.enable(region, keccak_row)?;

        // start over to accumulate big-endian bytes of keccak output
        rpi_rlc_acc = Value::known(F::zero());
        offset += 1;
        // the high 16 bytes of keccak output
        let mut cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &keccak.to_fixed_bytes()[..16],
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            challenges,
            true,
        )?;
        let keccak_hi_cell = cells[RPI_CELL_IDX].clone();

        // the low 16 bytes of keccak output
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &keccak.to_fixed_bytes()[16..],
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            challenges,
            true,
        )?;
        let keccak_lo_cell = cells[RPI_CELL_IDX].clone();

        region.constrain_equal(
            keccak_output_cell.cell(),
            cells[RPI_RLC_ACC_CELL_IDX].cell(),
        )?;

        Ok((keccak_hi_cell, keccak_lo_cell))
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_field_in_pi(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        value_bytes: &[u8],
        rpi_rlc_acc: &mut Value<F>,
        rpi_length_acc: &mut u64,
        is_block: bool,
        skip_for_keccak: bool,
        challenges: &Challenges<Value<F>>,
        keccak_hi_lo: bool,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let len = value_bytes.len();

        let mut value_bytes_acc = Value::known(F::zero());
        let (use_rlc, t) = if len * 8 > F::CAPACITY as usize {
            (F::one(), challenges.evm_word())
        } else {
            (F::zero(), Value::known(F::from(BYTE_POW_BASE)))
        };
        let r = if keccak_hi_lo {
            challenges.evm_word()
        } else {
            challenges.keccak_input()
        };
        let value = value_bytes
            .iter()
            .fold(Value::known(F::zero()), |acc, byte| {
                acc.zip(t)
                    .and_then(|(acc, t)| Value::known(acc * t + F::from(*byte as u64)))
            });

        let mut cells = vec![None; 2 + value_bytes.len()];
        for (i, byte) in value_bytes.iter().enumerate() {
            let row_offset = *offset + i;

            let real_value = if skip_for_keccak {
                Value::known(F::zero())
            } else {
                value
            };
            *rpi_length_acc += if skip_for_keccak { 0 } else { 1 };
            // calculate acc
            value_bytes_acc = value_bytes_acc
                .zip(t)
                .and_then(|(acc, t)| Value::known(acc * t + F::from(*byte as u64)));

            if !skip_for_keccak {
                *rpi_rlc_acc = rpi_rlc_acc
                    .zip(r)
                    .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)));
            }

            // set field-related selectors
            if i == 0 {
                self.q_field_start.enable(region, row_offset)?;
            }
            if i == len - 1 {
                self.q_field_end.enable(region, row_offset)?;
            } else {
                self.q_field_step.enable(region, row_offset)?;
            }

            region.assign_fixed(
                || "is_field_rlc",
                self.is_field_rlc,
                row_offset,
                || Value::known(use_rlc),
            )?;
            let field_byte_cell = region.assign_advice(
                || "field byte",
                self.rpi_field_bytes,
                row_offset,
                || Value::known(F::from(*byte as u64)),
            )?;
            region.assign_advice(
                || "field byte acc",
                self.rpi_field_bytes_acc,
                row_offset,
                || value_bytes_acc,
            )?;
            let rpi_cell = region.assign_advice(
                || "field value",
                self.raw_public_inputs,
                row_offset,
                || value,
            )?;
            let rpi_rlc_cell = region.assign_advice(
                || "rpi_rlc_acc",
                self.rpi_rlc_acc,
                row_offset,
                || *rpi_rlc_acc,
            )?;
            region.assign_advice(
                || "is_rpi_padding",
                self.is_rpi_padding,
                row_offset,
                || Value::known(F::from(skip_for_keccak as u64)),
            )?;
            let real_rpi_cell =
                region.assign_advice(|| "real_rpi", self.real_rpi, row_offset, || real_value)?;
            region.assign_advice(
                || "rpi_length_acc",
                self.rpi_length_acc,
                row_offset,
                || Value::known(F::from(*rpi_length_acc)),
            )?;

            if i == len - 1 {
                cells[RPI_CELL_IDX] = if is_block {
                    Some(real_rpi_cell)
                } else {
                    Some(rpi_cell)
                };
                cells[RPI_RLC_ACC_CELL_IDX] = Some(rpi_rlc_cell);
            }
            cells[2 + i] = Some(field_byte_cell);
        }
        *offset += len;

        Ok(cells.into_iter().map(|cell| cell.unwrap()).collect())
    }

    fn assign_block_table(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData,
        max_inner_blocks: usize,
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let mut offset = 0;

        let block_tag_chip = BinaryNumberChip::construct(self.block_tag_bits);
        let block_table_columns = <BlockTable as LookupTable<F>>::advice_columns(&self.block_table);

        region.assign_fixed(
            || "block table all-zero row for fixed",
            self.q_block_tag,
            offset,
            || Value::known(F::zero()),
        )?;
        for column in block_table_columns
            .iter()
            .chain(iter::once(&self.cum_num_txs))
        {
            region.assign_advice(
                || "block table all-zero row",
                *column,
                offset,
                || Value::known(F::zero()),
            )?;
        }
        block_tag_chip.assign(region, offset, &BlockContextFieldTag::Null)?;
        offset += 1;

        let mut cum_num_txs = 0usize;
        let mut block_value_cells = vec![];
        let block_ctxs = &public_data.block_ctxs;
        for (block_idx, block_ctx) in block_ctxs
            .ctxs
            .values()
            .cloned()
            .chain(
                (block_ctxs.ctxs.len()..max_inner_blocks)
                    .into_iter()
                    .map(|_| BlockContext::default()),
            )
            .enumerate()
        {
            let num_txs = public_data
                .transactions
                .iter()
                .filter(|tx| tx.block_number == block_ctx.number.as_u64())
                .count();
            let tag = [
                Coinbase, Timestamp, Number, Difficulty, GasLimit, BaseFee, ChainId, NumTxs,
                CumNumTxs, BlockHash,
            ];
            let mut cum_num_txs_field = F::from(cum_num_txs as u64);
            cum_num_txs += num_txs;
            for (row, tag) in block_ctx
                .table_assignments(num_txs, cum_num_txs, challenges)
                .into_iter()
                .zip(tag.iter())
            {
                for (column, value) in block_table_columns.iter().zip_eq(row) {
                    let cell = region.assign_advice(
                        || format!("block table row {}", offset),
                        *column,
                        offset,
                        || value,
                    )?;
                    if *column == self.block_table.value {
                        block_value_cells.push(cell);
                    }
                }
                block_tag_chip.assign(region, offset, tag)?;
                if block_idx != max_inner_blocks - 1 || *tag != BlockHash {
                    // it's not the last row of block table
                    region.assign_fixed(
                        || "q_block_tag",
                        self.q_block_tag,
                        offset,
                        || Value::known(F::one()),
                    )?;
                }
                if *tag == CumNumTxs {
                    cum_num_txs_field = F::from(cum_num_txs as u64);
                }
                region.assign_advice(
                    || "cum_num_txs",
                    self.cum_num_txs,
                    offset,
                    || Value::known(cum_num_txs_field),
                )?;
                offset += 1;
            }
        }

        Ok(block_value_cells)
    }
}

/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct PiCircuit<F: Field> {
    max_txs: usize,
    max_calldata: usize,
    max_inner_blocks: usize,
    /// PublicInputs data known by the verifier
    pub public_data: PublicData,

    _marker: PhantomData<F>,
}

impl<F: Field> PiCircuit<F> {
    /// Creates a new PiCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        max_inner_blocks: usize,
        block: &Block<F>,
    ) -> Self {
        let context = block
            .context
            .ctxs
            .iter()
            .next()
            .map(|(_k, v)| v.clone())
            .unwrap_or_default();
        let public_data = PublicData {
            chain_id: context.chain_id,
            transactions: block.txs.clone(),
            block_ctxs: block.context.clone(),
            prev_state_root: H256(block.mpt_updates.old_root().to_be_bytes()),
            withdraw_trie_root: H256::zero(),
        };
        Self {
            public_data,
            max_txs,
            max_calldata,
            max_inner_blocks,
            _marker: PhantomData,
        }
    }

    /// Return txs
    pub fn txs(&self) -> &[Transaction] {
        &self.public_data.transactions
    }
}

impl<F: Field> SubCircuit<F> for PiCircuit<F> {
    type Config = PiCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        PiCircuit::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.circuits_params.max_inner_blocks,
            block,
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let row_num = |inner_block_num, tx_num| -> usize {
            BLOCK_HEADER_BYTES_NUM * inner_block_num + KECCAK_DIGEST_SIZE * tx_num + 33
        };
        (
            row_num(block.context.ctxs.len(), block.txs.len()),
            row_num(
                block.circuits_params.max_inner_blocks,
                block.circuits_params.max_txs,
            ),
        )
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let keccak_rpi = self.public_data.get_pi(self.max_txs);
        let keccak_hi = keccak_rpi
            .to_fixed_bytes()
            .iter()
            .take(16)
            .fold(F::zero(), |acc, byte| {
                acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
            });

        let keccak_lo = keccak_rpi
            .to_fixed_bytes()
            .iter()
            .skip(16)
            .fold(F::zero(), |acc, byte| {
                acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
            });

        let public_inputs = vec![keccak_hi, keccak_lo];
        vec![public_inputs]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let pi_cells = layouter.assign_region(
            || "pi region",
            |mut region| {
                // Annotate columns
                config.tx_table.annotate_columns_in_region(&mut region);
                config.block_table.annotate_columns_in_region(&mut region);

                // assign block table
                let block_value_cells = config.assign_block_table(
                    &mut region,
                    &self.public_data,
                    self.max_inner_blocks,
                    challenges,
                )?;
                // assign pi cols
                let (keccak_hi_cell, keccak_lo_cell) = config.assign(
                    &mut region,
                    &self.public_data,
                    &block_value_cells,
                    challenges,
                )?;

                Ok(vec![keccak_hi_cell, keccak_lo_cell])
            },
        )?;
        // TODO: add copy constraints between block_table.index and
        //       block_table.value (tag = 'Number') for tags except
        //       history_hashes

        // Constrain raw_public_input cells to public inputs
        for (i, pi_cell) in pi_cells.iter().enumerate() {
            layouter.constrain_instance(pi_cell.cell(), config.pi, i)?;
        }

        Ok(())
    }
}

// We define the PiTestCircuit as a wrapper over PiCircuit extended to take the
// generic const parameters MAX_TXS and MAX_CALLDATA.  This is necessary because
// the trait Circuit requires an implementation of `configure` that doesn't take
// any circuit parameters, and the PiCircuit defines gates that use rotations
// that depend on MAX_TXS and MAX_CALLDATA, so these two values are required
// during the configuration.
/// Test Circuit for PiCircuit
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
#[derive(Default, Clone)]
pub struct PiTestCircuit<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_INNER_BLOCKS: usize,
>(pub PiCircuit<F>);

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_INNER_BLOCKS: usize>
    SubCircuit<F> for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>
{
    type Config = PiCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);

        Self(PiCircuit::new_from_block(block))
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);

        PiCircuit::min_num_rows_block(block)
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        self.0.instance()
    }

    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        _layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        panic!("use PiCircuit for embedding instead");
    }
}

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_INNER_BLOCKS: usize>
    Circuit<F> for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>
{
    type Config = (PiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            PiCircuitConfig::new(
                meta,
                PiCircuitConfigArgs {
                    max_txs: MAX_TXS,
                    max_calldata: MAX_CALLDATA,
                    max_inner_blocks: MAX_INNER_BLOCKS,
                    block_table,
                    keccak_table,
                    tx_table,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);

        // assign tx table
        config.tx_table.load(
            &mut layouter,
            &self.0.public_data.transactions,
            self.0.max_txs,
            self.0.max_calldata,
            self.0.public_data.chain_id.as_u64(),
            &challenges,
        )?;
        // assign keccak table
        let rpi_bytes = self.0.public_data.raw_public_input_bytes(self.0.max_txs);
        config
            .keccak_table
            .dev_load(&mut layouter, vec![&rpi_bytes], &challenges)?;

        self.0.synthesize_sub(&config, &challenges, &mut layouter)?;

        Ok(())
    }
}

#[cfg(test)]
mod pi_circuit_test {
    use super::{PiCircuit, PiTestCircuit};
    use crate::{util::SubCircuit, witness::Block};
    use eth_types::Field;
    use halo2_proofs::dev::{MockProver, VerifyFailure};

    fn run<
        F: Field,
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
    >(
        k: u32,
        block: Block<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(PiCircuit::new(
            MAX_TXS,
            MAX_CALLDATA,
            MAX_INNER_BLOCKS,
            &block,
        ));
        let public_inputs = circuit.0.instance();

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    #[cfg(feature = "scroll")]
    #[test]
    fn serial_test_simple_pi() {
        use mock::test_ctx::{helpers::tx_from_1_to_0, SimpleTestContext};
        use std::env::set_var;

        use crate::witness::block_convert;
        use bus_mapping::mock::BlockData;
        use eth_types::{bytecode, geth_types::GethData};
        use halo2_proofs::halo2curves::bn256::Fr;
        use mock::{
            test_ctx::helpers::account_0_code_account_1_no_code, TestContext, MOCK_CHAIN_ID,
            MOCK_DIFFICULTY,
        };
        use pretty_assertions::assert_eq;

        const MAX_TXS: usize = 4;
        const MAX_CALLDATA: usize = 20;
        const MAX_INNER_BLOCKS: usize = 4;

        let mut difficulty_be_bytes = [0u8; 32];
        let mut chain_id_be_bytes = [0u8; 32];
        MOCK_DIFFICULTY.to_big_endian(&mut difficulty_be_bytes);
        MOCK_CHAIN_ID.to_big_endian(&mut chain_id_be_bytes);
        set_var("CHAIN_ID", hex::encode(chain_id_be_bytes));
        set_var("DIFFICULTY", hex::encode(difficulty_be_bytes));

        let bytecode = bytecode! {
            STOP
        };
        let test_ctx = SimpleTestContext::new(
            Some(vec![Word::zero()]),
            account_0_code_account_1_no_code(bytecode),
            tx_from_1_to_0,
            |block, _txs| block.number(0xcafeu64),
        )
        .unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db).unwrap();

        let k = 16;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(k, block),
            Ok(())
        );
    }

    // fn run_size_check<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    // public_data: [PublicData; 2],
    // ) {
    // let mut rng = ChaCha20Rng::seed_from_u64(2);
    // let randomness = F::random(&mut rng);
    // let rand_rpi = F::random(&mut rng);
    //
    // let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
    // MAX_TXS,
    // MAX_CALLDATA,
    // randomness,
    // rand_rpi,
    // public_data[0].clone(),
    // ));
    // let public_inputs = circuit.0.instance();
    // let prover1 = MockProver::run(20, &circuit, public_inputs).unwrap();
    //
    // let circuit2 = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
    // MAX_TXS,
    // MAX_CALLDATA,
    // randomness,
    // rand_rpi,
    // public_data[1].clone(),
    // ));
    // let public_inputs = circuit2.0.instance();
    // let prover2 = MockProver::run(20, &circuit, public_inputs).unwrap();
    //
    // assert_eq!(prover1.fixed(), prover2.fixed());
    // assert_eq!(prover1.permutation(), prover2.permutation());
    // }
    //
    // #[test]
    // fn variadic_size_check() {
    // const MAX_TXS: usize = 8;
    // const MAX_CALLDATA: usize = 200;
    //
    // let mut pub_dat_1 = PublicData {
    // chain_id: *MOCK_CHAIN_ID,
    // ..Default::default()
    // };
    //
    // let n_tx = 2;
    // for i in 0..n_tx {
    // pub_dat_1
    // .transactions
    // .push(CORRECT_MOCK_TXS[i].clone().into());
    // }
    //
    // let mut pub_dat_2 = PublicData {
    // chain_id: *MOCK_CHAIN_ID,
    // ..Default::default()
    // };
    //
    // let n_tx = 4;
    // for i in 0..n_tx {
    // pub_dat_2
    // .transactions
    // .push(CORRECT_MOCK_TXS[i].clone().into());
    // }
    //
    // run_size_check::<Fr, MAX_TXS, MAX_CALLDATA>([pub_dat_1, pub_dat_2]);
    // }
}
