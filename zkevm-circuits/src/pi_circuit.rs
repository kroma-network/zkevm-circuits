//! Public Input Circuit implementation

use ethers_core::k256::ecdsa::SigningKey;
use std::iter;
use std::marker::PhantomData;

use eth_types::geth_types::BlockConstants;
use eth_types::sign_types::SignData;
use eth_types::H256;
use eth_types::{
    geth_types::Transaction, Address, Field, ToBigEndian, ToLittleEndian, ToScalar, Word,
};
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{Block, Bytes, TransactionRequest};
use ethers_core::utils::keccak256;
use ethers_signers::{Signer, Wallet};
use halo2_proofs::plonk::{Fixed, Instance};

use crate::table::TxFieldTag;
use crate::table::TxTable;
use crate::table::{BlockTable, KeccakTable, RlpTable};
use crate::util::{random_linear_combine_word as rlc, U256};
use crate::witness::signed_tx_from_geth_tx;
use gadgets::util::Expr;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

/// Fixed by the spec
const TX_LEN: usize = 9;
const BLOCK_LEN: usize = 7 + 256;
const EXTRA_LEN: usize = 2;
const BYTE_POW_BASE: u64 = 1 << 8;

/// Values of the block table (as in the spec)
#[derive(Clone, Default, Debug)]
pub struct BlockValues {
    coinbase: Address,
    gas_limit: u64,
    number: u64,
    timestamp: u64,
    difficulty: Word,
    base_fee: Word, // NOTE: BaseFee was added by EIP-1559 and is ignored in legacy headers.
    chain_id: u64,
    history_hashes: Vec<H256>,
}

/// Values of the tx table (as in the spec)
#[derive(Default, Debug, Clone)]
pub struct TxValues {
    nonce: u64,
    gas: u64, //gas limit
    gas_price: Word,
    from_addr: Address,
    to_addr: Address,
    is_create: u64,
    value: Word,
    call_data_len: u64,
    call_data_gas_cost: u64,
    v: u64,
    r: Word,
    s: Word,
    tx_sign_hash: [u8; 32],
    tx_hash: H256,
}

/// Extra values (not contained in block or tx tables)
#[derive(Default, Debug, Clone)]
pub struct ExtraValues {
    // block_hash: H256,
    state_root: H256,
    prev_state_root: H256,
}

/// PublicData contains all the values that the PiCircuit recieves as input
#[derive(Debug, Clone, Default)]
pub struct PublicData {
    /// chain id
    pub chain_id: Word,
    /// History hashes contains the most recent 256 block hashes in history,
    /// where the latest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block from geth
    pub eth_block: Block<eth_types::Transaction>,
    /// Constants related to Ethereum block
    pub block_constants: BlockConstants,
    /// Previous block root
    pub prev_state_root: H256,
}

impl PublicData {
    /// Returns struct with values for the block table
    pub fn get_block_table_values(&self) -> BlockValues {
        let history_hashes = [
            vec![H256::zero(); 256 - self.history_hashes.len()],
            self.history_hashes
                .iter()
                .map(|&hash| H256::from(hash.to_be_bytes()))
                .collect(),
        ]
        .concat();
        BlockValues {
            coinbase: self.block_constants.coinbase,
            gas_limit: self.block_constants.gas_limit.as_u64(),
            number: self.block_constants.number.as_u64(),
            timestamp: self.block_constants.timestamp.as_u64(),
            difficulty: self.block_constants.difficulty,
            base_fee: self.block_constants.base_fee,
            chain_id: self.chain_id.as_u64(),
            history_hashes,
        }
    }

    /// Returns struct with values for the tx table
    pub fn get_tx_table_values(&self) -> Vec<TxValues> {
        let chain_id: u64 = self
            .chain_id
            .try_into()
            .expect("Error converting chain_id to u64");
        let mut tx_vals = vec![];
        for tx in &self.txs() {
            let sign_data: SignData = tx
                .sign_data(chain_id)
                .expect("Error computing tx_sign_hash");
            let mut msg_hash_le = [0u8; 32];
            msg_hash_le.copy_from_slice(sign_data.msg_hash.to_bytes().as_slice());
            tx_vals.push(TxValues {
                nonce: tx.nonce.as_u64(),
                gas_price: tx.gas_price,
                gas: tx.gas_limit.as_u64(),
                from_addr: tx.from,
                to_addr: tx.to.unwrap_or_else(Address::zero),
                is_create: (tx.to.is_none() as u64),
                value: tx.value,
                call_data_len: tx.call_data.0.len() as u64,
                call_data_gas_cost: tx.call_data.iter().fold(0, |acc, b| {
                    if *b == 0 {
                        acc + 4
                    } else {
                        acc + 16
                    }
                }),
                v: tx.v,
                r: tx.r,
                s: tx.s,
                tx_sign_hash: msg_hash_le,
                tx_hash: tx.hash,
            });
        }
        tx_vals
    }

    /// Returns struct with the extra values
    pub fn get_extra_values(&self) -> ExtraValues {
        ExtraValues {
            // block_hash: self.eth_block.hash.unwrap_or_else(H256::zero),
            state_root: self.eth_block.state_root,
            prev_state_root: self.prev_state_root,
        }
    }

    fn txs(&self) -> Vec<Transaction> {
        self.eth_block
            .transactions
            .iter()
            .map(Transaction::from)
            .collect()
    }
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    block_table: BlockTable,
    tx_table: TxTable,
    keccak_table: KeccakTable,
    rlp_table: RlpTable,

    raw_public_inputs: Column<Advice>, // block, extra, tx hashes
    rpi_field_bytes: Column<Advice>,   // rpi in bytes
    rpi_field_bytes_acc: Column<Advice>,
    rpi_rlc_acc: Column<Advice>, // RLC(rpi) as the input to Keccak table
    rand_rpi: Column<Advice>,    // randomness for RLC

    q_field_start: Selector,
    q_field_step: Selector,
    is_field_rlc: Column<Fixed>,
    q_field_end: Selector,

    q_start: Selector,
    q_not_end: Selector,
    q_keccak: Selector,

    pi: Column<Instance>, // rpi_rand, rlc(keccak(rpi))

    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    PiCircuitConfig<F, MAX_TXS, MAX_CALLDATA>
{
    /// Return a new PiCircuitConfig
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        block_table: BlockTable,
        tx_table: TxTable,
        rlp_table: RlpTable,
        keccak_table: KeccakTable,
    ) -> Self {
        let rpi = meta.advice_column();
        let rpi_bytes = meta.advice_column();
        let rpi_bytes_acc = meta.advice_column();
        let rpi_rlc_acc = meta.advice_column();
        let rand_rpi = meta.advice_column();

        let pi = meta.instance_column();

        let q_field_start = meta.complex_selector();
        let q_field_step = meta.complex_selector();
        let q_field_end = meta.complex_selector();
        let is_field_rlc = meta.fixed_column();

        let q_start = meta.complex_selector();
        let q_not_end = meta.complex_selector();
        let q_keccak = meta.complex_selector();

        meta.enable_equality(rpi);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(block_table.value); // copy block to rpi
        meta.enable_equality(tx_table.value); // copy tx hashes to rpi

        meta.enable_equality(rand_rpi); // pi[0] == rand_rpi
        meta.enable_equality(pi);

        // field bytes
        meta.create_gate(
            "rpi_field_bytes_acc[i+1] = rpi_field_bytes_acc[i] * t + rpi_field_bytes[i+1]",
            |meta| {
                let bytes_acc_next = meta.query_advice(rpi_bytes_acc, Rotation::next());
                let bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
                let bytes_next = meta.query_advice(rpi_bytes, Rotation::next());
                let q_field_step = meta.query_selector(q_field_step);
                let is_field_rlc = meta.query_fixed(is_field_rlc, Rotation::cur());
                let rand = meta.query_advice(rand_rpi, Rotation::cur());
                let t =
                    is_field_rlc.expr() * rand + (1.expr() - is_field_rlc) * BYTE_POW_BASE.expr();

                vec![q_field_step * (bytes_acc_next - (bytes_acc * t + bytes_next))]
            },
        );
        meta.create_gate("rpi_field_bytes_acc = rpi", |meta| {
            let q_field_end = meta.query_selector(q_field_end);
            let rpi_field_bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
            let rpi = meta.query_advice(rpi, Rotation::cur());

            vec![q_field_end * (rpi - rpi_field_bytes_acc)]
        });
        meta.create_gate("rpi_field_bytes_acc = rpi_field_bytes", |meta| {
            let q_field_start = meta.query_selector(q_field_start);
            let rpi_field_bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
            let rpi_field_bytes = meta.query_advice(rpi_bytes, Rotation::cur());

            vec![q_field_start * (rpi_field_bytes_acc - rpi_field_bytes)]
        });

        // rpi_rlc
        meta.create_gate(
            "rpi_rlc_acc[i+1] = rand_rpi * rpi_rlc_acc[i] + rpi_field_bytes[i+1]",
            |meta| {
                // q_not_end * row_next.rpi_rlc_acc ==
                // (q_not_end * row.rpi_rlc_acc * row.rand_rpi + row_next.rpi_field_bytes )
                let q_not_end = meta.query_selector(q_not_end);
                let rpi_rlc_acc_cur = meta.query_advice(rpi_rlc_acc, Rotation::cur());
                let rpi_rlc_acc_next = meta.query_advice(rpi_rlc_acc, Rotation::next());
                let rand_rpi = meta.query_advice(rand_rpi, Rotation::cur());
                let rpi_bytes_next = meta.query_advice(rpi_bytes, Rotation::next());

                vec![q_not_end * (rpi_rlc_acc_cur * rand_rpi + rpi_bytes_next - rpi_rlc_acc_next)]
            },
        );
        meta.create_gate("rpi_rlc_acc[0] = rpi_bytes[0]", |meta| {
            let q_start = meta.query_selector(q_start);
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            let rpi_bytes = meta.query_advice(rpi_bytes, Rotation::cur());

            vec![q_start * (rpi_rlc_acc - rpi_bytes)]
        });

        // rand_rpi[i] == rand_rpi[j]
        meta.create_gate("rand_pi = rand_rpi.next", |meta| {
            // q_not_end * row.rand_rpi == q_not_end * row_next.rand_rpi
            let q_not_end = meta.query_selector(q_not_end);
            let cur_rand_rpi = meta.query_advice(rand_rpi, Rotation::cur());
            let next_rand_rpi = meta.query_advice(rand_rpi, Rotation::next());

            vec![q_not_end * (cur_rand_rpi - next_rand_rpi)]
        });

        meta.lookup_any("keccak(rpi)", |meta| {
            let is_enabled = meta.query_advice(keccak_table.is_enabled, Rotation::cur());
            let input_rlc = meta.query_advice(keccak_table.input_rlc, Rotation::cur());
            let input_len = meta.query_advice(keccak_table.input_len, Rotation::cur());
            let output_rlc = meta.query_advice(keccak_table.output_rlc, Rotation::cur());
            let q_keccak = meta.query_selector(q_keccak);

            let rpi_rlc = meta.query_advice(rpi_rlc_acc, Rotation::prev());
            let output = meta.query_advice(rpi, Rotation::cur());

            vec![
                (q_keccak.expr() * 1.expr(), is_enabled),
                (q_keccak.expr() * rpi_rlc, input_rlc),
                (q_keccak.expr() * 1.expr(), input_len),
                (q_keccak * output, output_rlc),
            ]
        });

        Self {
            block_table,
            tx_table,
            rlp_table,
            keccak_table,
            raw_public_inputs: rpi,
            rpi_field_bytes: rpi_bytes,
            rpi_field_bytes_acc: rpi_bytes_acc,
            rpi_rlc_acc,
            rand_rpi,
            q_field_start,
            q_field_step,
            is_field_rlc,
            q_field_end,
            q_start,
            q_not_end,
            q_keccak,
            pi,
            _marker: PhantomData,
        }
    }

    fn assign_field_in_pi(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        value: F,
        value_bytes: &[u8],
        rand: F,
        rpi_rlc_acc: &mut F,
        is_last: bool,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let len = value_bytes.len();
        let (use_rlc, t) = if value_bytes.len() * 8 > F::CAPACITY as usize {
            (F::one(), rand)
        } else {
            (F::zero(), F::from(BYTE_POW_BASE))
        };
        let mut value_bytes_acc = F::zero();
        let mut rand_cell = None;
        let mut rpi_rlc_cell = None;
        for (i, byte) in value_bytes.into_iter().enumerate() {
            let row_offset = *offset + i;
            value_bytes_acc = value_bytes_acc * t + F::from(*byte as u64);
            *rpi_rlc_acc = *rpi_rlc_acc * rand + F::from(*byte as u64);
            if i == 0 {
                self.q_field_start.enable(region, row_offset)?;
            }
            if i == len - 1 {
                self.q_field_end.enable(region, row_offset)?;
            } else {
                self.q_field_step.enable(region, row_offset)?;
            }
            if !is_last || i < (len - 1) {
                self.q_not_end.enable(region, row_offset)?;
            }
            region.assign_fixed(
                || "is_field_rlc",
                self.is_field_rlc,
                row_offset,
                || Value::known(use_rlc),
            )?;
            region.assign_advice(
                || "field byte",
                self.rpi_field_bytes,
                row_offset,
                || Value::known(F::from(*byte as u64)),
            )?;
            region.assign_advice(
                || "field byte acc",
                self.rpi_field_bytes_acc,
                row_offset,
                || Value::known(value_bytes_acc),
            )?;
            region.assign_advice(
                || "field value",
                self.raw_public_inputs,
                row_offset,
                || Value::known(value),
            )?;
            let _rpi_rlc_cell = region.assign_advice(
                || "rpi_rlc_acc",
                self.rpi_rlc_acc,
                row_offset,
                || Value::known(*rpi_rlc_acc),
            )?;
            let _rand_cell = region.assign_advice(
                || "rand_rpi",
                self.rand_rpi,
                row_offset,
                || Value::known(rand),
            )?;
            if i == len - 1 {
                rpi_rlc_cell = Some(_rpi_rlc_cell);
            }
            if i == 0 {
                rand_cell = Some(_rand_cell);
            }
        }
        *offset += len;

        Ok((rand_cell.unwrap(), rpi_rlc_cell.unwrap()))
    }

    /// Assigns a tx_table row and stores the values in a vec for the
    /// raw_public_inputs column
    #[allow(clippy::too_many_arguments)]
    fn assign_tx_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tag: TxFieldTag,
        index: usize,
        tx_value: F,
    ) -> Result<(), Error> {
        let tx_id = F::from(tx_id as u64);
        let tag = F::from(tag as u64);
        let index = F::from(index as u64);

        // Assign vals to Tx_table
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            offset,
            || Value::known(tx_id),
        )?;
        region.assign_fixed(|| "tag", self.tx_table.tag, offset, || Value::known(tag))?;
        region.assign_advice(
            || "index",
            self.tx_table.index,
            offset,
            || Value::known(index),
        )?;
        region.assign_advice(
            || "tx_value",
            self.tx_table.value,
            offset,
            || Value::known(tx_value),
        )?;

        Ok(())
    }

    /// Assigns the values for block table in the block_table column
    /// and in the raw_public_inputs column. A copy is also stored in
    /// a vector for computing RLC(raw_public_inputs)
    fn assign_block_table(
        &self,
        region: &mut Region<'_, F>,
        block_values: BlockValues,
        randomness: F,
    ) -> Result<(), Error> {
        let mut offset = 0;

        // zero row
        region.assign_advice(
            || "zero",
            self.block_table.value,
            offset,
            || Value::known(F::zero()),
        )?;
        offset += 1;

        // coinbase
        let coinbase: F = block_values.coinbase.to_scalar().unwrap();
        region.assign_advice(
            || "coinbase",
            self.block_table.value,
            offset,
            || Value::known(coinbase),
        )?;
        offset += 1;

        // gas_limit
        let gas_limit = F::from(block_values.gas_limit);
        region.assign_advice(
            || "gas_limit",
            self.block_table.value,
            offset,
            || Value::known(gas_limit),
        )?;
        offset += 1;

        // number
        let number = F::from(block_values.number);
        region.assign_advice(
            || "number",
            self.block_table.value,
            offset,
            || Value::known(number),
        )?;
        offset += 1;

        // timestamp
        let timestamp = F::from(block_values.timestamp);
        region.assign_advice(
            || "timestamp",
            self.block_table.value,
            offset,
            || Value::known(timestamp),
        )?;
        offset += 1;

        // difficulty
        let difficulty = rlc(block_values.difficulty.to_le_bytes(), randomness);
        region.assign_advice(
            || "difficulty",
            self.block_table.value,
            offset,
            || Value::known(difficulty),
        )?;
        offset += 1;

        // base_fee
        let base_fee = rlc(block_values.base_fee.to_le_bytes(), randomness);
        region.assign_advice(
            || "base_fee",
            self.block_table.value,
            offset,
            || Value::known(base_fee),
        )?;
        offset += 1;

        // chain_id
        let chain_id = F::from(block_values.chain_id);
        region.assign_advice(
            || "chain_id",
            self.block_table.value,
            offset,
            || Value::known(chain_id),
        )?;
        offset += 1;

        for prev_hash in block_values.history_hashes {
            let prev_hash = rlc(prev_hash.to_fixed_bytes(), randomness);
            region.assign_advice(
                || "prev_hash",
                self.block_table.value,
                offset,
                || Value::known(prev_hash),
            )?;
            offset += 1;
        }

        Ok(())
    }

    /// Assigns the extra fields (not in block or tx tables):
    ///   - state root
    ///   - previous block state root
    /// to the raw_public_inputs column and stores a copy in a
    /// vector for computing RLC(raw_public_inputs).
    fn assign_extra_fields(
        &self,
        region: &mut Region<'_, F>,
        extra: ExtraValues,
        randomness: F,
    ) -> Result<[AssignedCell<F, F>; 2], Error> {
        let mut offset = BLOCK_LEN + 1;
        // block hash
        // let block_hash = rlc(extra.block_hash.to_fixed_bytes(), randomness);
        // region.assign_advice(
        //     || "block.hash",
        //     self.raw_public_inputs,
        //     offset,
        //     || Ok(block_hash),
        // )?;
        // raw_pi_vals[offset] = block_hash;
        // offset += 1;

        // block state root
        let state_root = rlc(extra.state_root.to_fixed_bytes(), randomness);
        let state_root_cell = region.assign_advice(
            || "state.root",
            self.raw_public_inputs,
            offset,
            || Value::known(state_root),
        )?;
        offset += 1;

        // previous block state root
        let prev_state_root = rlc(extra.prev_state_root.to_fixed_bytes(), randomness);
        let prev_state_root_cell = region.assign_advice(
            || "parent_block.hash",
            self.raw_public_inputs,
            offset,
            || Value::known(prev_state_root),
        )?;
        Ok([state_root_cell, prev_state_root_cell])
    }

    /// Assign `rpi_rlc_acc` and `rand_rpi` columns
    #[allow(clippy::type_complexity)]
    fn assign_rlc_pi(
        &self,
        region: &mut Region<'_, F>,
        block_values: BlockValues,
        rand_rpi: F,
        tx_hashes: Vec<H256>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let mut offset = 0;
        let mut rpi_rlc_acc = F::zero();
        let dummy_tx_hash = get_dummy_tx_hash(block_values.chain_id);

        self.q_start.enable(region, offset)?;
        // Assign fields in block table
        // coinbase
        self.assign_field_in_pi(
            region,
            &mut offset,
            block_values.coinbase.to_scalar().unwrap(),
            &block_values.coinbase.to_fixed_bytes(),
            rand_rpi,
            &mut rpi_rlc_acc,
            false,
        )?;
        // gas_limit
        self.assign_field_in_pi(
            region,
            &mut offset,
            F::from(block_values.gas_limit),
            &block_values.gas_limit.to_be_bytes(),
            rand_rpi,
            &mut rpi_rlc_acc,
            false,
        )?;
        // number
        self.assign_field_in_pi(
            region,
            &mut offset,
            F::from(block_values.number),
            &block_values.number.to_be_bytes(),
            rand_rpi,
            &mut rpi_rlc_acc,
            false,
        )?;
        // timestamp
        self.assign_field_in_pi(
            region,
            &mut offset,
            F::from(block_values.timestamp),
            &block_values.timestamp.to_be_bytes(),
            rand_rpi,
            &mut rpi_rlc_acc,
            false,
        )?;
        // difficulty
        self.assign_field_in_pi(
            region,
            &mut offset,
            rlc(block_values.difficulty.to_le_bytes(), rand_rpi),
            &block_values.difficulty.to_be_bytes(),
            rand_rpi,
            &mut rpi_rlc_acc,
            false,
        )?;
        // base_fee
        self.assign_field_in_pi(
            region,
            &mut offset,
            rlc(block_values.base_fee.to_le_bytes(), rand_rpi),
            &block_values.base_fee.to_be_bytes(),
            rand_rpi,
            &mut rpi_rlc_acc,
            false,
        )?;
        // chain_id
        self.assign_field_in_pi(
            region,
            &mut offset,
            F::from(block_values.chain_id),
            &block_values.chain_id.to_be_bytes(),
            rand_rpi,
            &mut rpi_rlc_acc,
            false,
        )?;
        debug_assert_eq!(offset, 116);

        // assign history block hashes
        for prev_hash in block_values.history_hashes {
            let mut prev_hash_le_bytes = prev_hash.to_fixed_bytes();
            prev_hash_le_bytes.reverse();
            self.assign_field_in_pi(
                region,
                &mut offset,
                rlc(prev_hash_le_bytes, rand_rpi),
                &prev_hash.to_fixed_bytes(),
                rand_rpi,
                &mut rpi_rlc_acc,
                false,
            )?;
        }

        // assign tx hashes
        let num_txs = tx_hashes.len();
        let mut cells = None;
        for (i, tx_hash) in tx_hashes
            .into_iter()
            .chain((0..MAX_TXS - num_txs).into_iter().map(|_| dummy_tx_hash))
            .enumerate()
        {
            let mut tx_hash_le_bytes = tx_hash.to_fixed_bytes();
            tx_hash_le_bytes.reverse();
            cells = Some(self.assign_field_in_pi(
                region,
                &mut offset,
                rlc(tx_hash_le_bytes, rand_rpi),
                &tx_hash.to_fixed_bytes(),
                rand_rpi,
                &mut rpi_rlc_acc,
                i == MAX_TXS - 1,
            )?);
        }

        // assign rpi_acc, keccak_rpi
        let (rand_cell, rpi_rlc_cell) = cells.unwrap();
        let keccak_input_cell = rpi_rlc_cell.copy_advice(
            || "keccak(rpi)_input",
            region,
            self.raw_public_inputs,
            offset,
        )?;
        // let keccak_output = region.assign_advice(
        //     || "keccak(rpi)_output",
        //     self.rpi_rlc_acc,
        //     offset,
        //     || Value::known(F::zero())
        // )?;

        Ok((rand_cell, keccak_input_cell))
    }
}

/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct PiCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    /// Randomness for RLC encdoing
    pub randomness: F,

    /// Randomness for PI encoding
    pub rand_rpi: F,

    /// PublicInputs data known by the verifier
    pub public_data: PublicData,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    PiCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    /// Creates a new PiCircuit
    pub fn new(randomness: impl Into<F>, rand_rpi: impl Into<F>, public_data: PublicData) -> Self {
        Self {
            randomness: randomness.into(),
            rand_rpi: rand_rpi.into(),
            public_data,
        }
    }
}
impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for PiCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = PiCircuitConfig<F, MAX_TXS, MAX_CALLDATA>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let rlp_table = RlpTable::construct(meta);
        PiCircuitConfig::new(meta, block_table, tx_table, rlp_table, keccak_table)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let pi_cells = layouter.assign_region(
            || "region 0",
            |mut region| {
                // Assign block table
                let block_values = self.public_data.get_block_table_values();
                config.assign_block_table(&mut region, block_values.clone(), self.randomness)?;

                // Assign extra fields
                // let extra_vals = self.public_data.get_extra_values();
                // let [state_root, prev_state_root] = config.assign_extra_fields(
                //     &mut region,
                //     extra_vals,
                //     self.randomness,
                // )?;

                let mut offset = 0;
                // Assign Tx table
                let txs = self.public_data.get_tx_table_values();
                assert!(txs.len() <= MAX_TXS);
                let tx_default = TxValues::default();

                // Add empty row
                config.assign_tx_row(&mut region, offset, 0, TxFieldTag::Null, 0, F::zero())?;
                offset += 1;

                for i in 0..MAX_TXS {
                    let tx = if i < txs.len() { &txs[i] } else { &tx_default };

                    for (tag, value) in &[
                        (TxFieldTag::Nonce, F::from(tx.nonce)),
                        (TxFieldTag::Gas, F::from(tx.gas)),
                        (
                            TxFieldTag::GasPrice,
                            rlc(tx.gas_price.to_le_bytes(), self.randomness),
                        ),
                        (
                            TxFieldTag::CallerAddress,
                            tx.from_addr.to_scalar().expect("tx.from too big"),
                        ),
                        (
                            TxFieldTag::CalleeAddress,
                            tx.to_addr.to_scalar().expect("tx.to too big"),
                        ),
                        (TxFieldTag::IsCreate, F::from(tx.is_create)),
                        (
                            TxFieldTag::Value,
                            rlc(tx.value.to_le_bytes(), self.randomness),
                        ),
                        (TxFieldTag::CallDataLength, F::from(tx.call_data_len)),
                        (TxFieldTag::CallDataGasCost, F::from(tx.call_data_gas_cost)),
                        (TxFieldTag::SigV, F::from(tx.v)),
                        (TxFieldTag::SigR, rlc(tx.r.to_le_bytes(), self.randomness)),
                        (TxFieldTag::SigV, rlc(tx.s.to_le_bytes(), self.randomness)),
                        (
                            TxFieldTag::TxSignHash,
                            rlc(tx.tx_sign_hash, self.randomness),
                        ),
                        (
                            TxFieldTag::TxHash,
                            rlc(tx.tx_hash.to_fixed_bytes(), self.randomness),
                        ),
                    ] {
                        config.assign_tx_row(&mut region, offset, i + 1, *tag, 0, *value)?;
                        offset += 1;
                    }
                }
                // Tx Table CallData
                let mut calldata_count = 0;
                for (i, tx) in self.public_data.txs().iter().enumerate() {
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < MAX_CALLDATA);
                        config.assign_tx_row(
                            &mut region,
                            offset,
                            i + 1,
                            TxFieldTag::CallData,
                            index,
                            F::from(*byte as u64),
                        )?;
                        offset += 1;
                        calldata_count += 1;
                    }
                }
                for _ in calldata_count..MAX_CALLDATA {
                    config.assign_tx_row(
                        &mut region,
                        offset,
                        0, // tx_id
                        TxFieldTag::CallData,
                        0,
                        F::zero(),
                    )?;
                    offset += 1;
                }

                // rpi_rlc and rand_rpi cols
                let (rand_cell, keccak_input_cell) = config.assign_rlc_pi(
                    &mut region,
                    block_values,
                    self.rand_rpi,
                    self.public_data
                        .get_tx_table_values()
                        .iter()
                        .map(|tx| tx.tx_hash.clone())
                        .collect(),
                )?;

                Ok(vec![rand_cell, keccak_input_cell])
            },
        )?;

        // assign rlp table
        // config.rlp_table.dev_load(
        //     &mut layouter,
        //
        // )?;

        // assign keccak table
        // config.keccak_table.dev_load(
        //     &mut layouter,
        //     signed_tx_from_geth_tx(&self.public_data.eth_block.transactions,
        //         self.public_data.chain_id.as_u64(),
        //     ),
        //     self.rand_rpi,
        // )?;

        // Constrain raw_public_input cells to public inputs
        for (i, pi_cell) in pi_cells.iter().enumerate() {
            layouter.constrain_instance(pi_cell.cell(), config.pi, i)?;
        }

        Ok(())
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    PiCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    /// Compute the public inputs for this circuit.
    pub fn instance(&self) -> Vec<Vec<F>> {
        let rpi_bytes = raw_public_input_bytes::<F, MAX_TXS, MAX_CALLDATA>(&self.public_data);

        // Computation of raw_pulic_inputs
        let rlc_rpi = rpi_bytes.iter().fold(F::zero(), |acc, val| {
            acc * self.rand_rpi + F::from(*val as u64)
        });
        let keccak_rpi = keccak256(rpi_bytes);
        let rlc_keccak = keccak_rpi.iter().rev().fold(F::zero(), |acc, val| {
            acc * self.rand_rpi + F::from(*val as u64)
        });

        // let block_hash = public_data
        //     .eth_block
        //     .hash
        //     .unwrap_or_else(H256::zero)
        //     .to_fixed_bytes();

        let public_inputs = vec![self.rand_rpi, rlc_rpi, rlc_keccak];

        vec![public_inputs]
    }
}

/// Get the tx hash of the dummy tx (nonce=0, gas=0, gas_price=0, to=0, value=0,
/// data="") for any chain_id
fn get_dummy_tx_hash(chain_id: u64) -> H256 {
    let mut sk_be_scalar = [0u8; 32];
    sk_be_scalar[31] = 1_u8;

    let sk = SigningKey::from_bytes(&sk_be_scalar).expect("sign key = 1");
    let wallet = Wallet::from(sk);

    let tx_req = TransactionRequest::new()
        .nonce(0)
        .gas(0)
        .gas_price(U256::zero())
        .to(Address::zero())
        .value(U256::zero())
        .data(Bytes::default())
        .chain_id(chain_id);

    let tx = TypedTransaction::Legacy(tx_req);
    let sig = wallet.sign_transaction_sync(&tx);

    let tx_hash = keccak256(tx.rlp_signed(&sig));

    log::debug!(
        "tx hash: {} from {:?}",
        hex::encode(tx_hash),
        wallet.address()
    );

    H256(tx_hash)
}

/// Compute the raw_public_inputs bytes from the verifier's perspective.
fn raw_public_input_bytes<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    public_data: &PublicData,
) -> Vec<u8> {
    let block = public_data.get_block_table_values();
    // let extra = public_data.get_extra_values();
    let txs = public_data.get_tx_table_values();
    let dummy_tx_hash = get_dummy_tx_hash(public_data.chain_id.as_u64());

    let result = iter::empty()
        // Block Values
        .chain(block.coinbase.to_fixed_bytes())
        .chain(block.gas_limit.to_be_bytes())
        .chain(block.number.to_be_bytes())
        .chain(block.timestamp.to_be_bytes())
        .chain(block.difficulty.to_be_bytes())
        .chain(block.base_fee.to_be_bytes())
        .chain(block.chain_id.to_be_bytes())
        .chain(
            block
                .history_hashes
                .iter()
                .flat_map(|tx_hash| tx_hash.to_fixed_bytes()),
        )
        // .chain(
        //     extra.state_root.to_fixed_bytes()
        // )
        // .chain(
        //     extra.prev_state_root.to_fixed_bytes()
        // )
        // Tx Hashes
        .chain(txs.iter().flat_map(|tx| tx.tx_hash.to_fixed_bytes()))
        .chain(
            (0..(MAX_TXS - txs.len()))
                .into_iter()
                .flat_map(|_| dummy_tx_hash.to_fixed_bytes()),
        )
        .collect::<Vec<u8>>();

    assert_eq!(
        result.len(),
        20 + 96 + 32 * block.history_hashes.len() + 32 * MAX_TXS
    );
    result
}

#[cfg(test)]
mod pi_circuit_test {
    use super::*;

    use crate::test_util::rand_tx;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        k: u32,
        public_data: PublicData,
    ) -> Result<(), Vec<VerifyFailure>> {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let randomness = F::random(&mut rng);
        let rand_rpi = F::random(&mut rng);

        let circuit = PiCircuit::<F, MAX_TXS, MAX_CALLDATA> {
            randomness,
            rand_rpi,
            public_data,
        };
        let public_inputs = circuit.instance();

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    #[test]
    fn test_default_pi() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 8;
        let public_data = PublicData::default();

        let k = 16;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    }

    #[test]
    fn test_simple_pi() {
        const MAX_TXS: usize = 4;
        const MAX_CALLDATA: usize = 20;

        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let mut public_data = PublicData::default();
        let chain_id = 1337u64;
        public_data.chain_id = Word::from(chain_id);
        public_data.block_constants.coinbase = Address::random();
        public_data.block_constants.difficulty = U256::one();

        let n_tx = 2;
        for _ in 0..n_tx {
            let eth_tx = eth_types::Transaction::from(&rand_tx(&mut rng, chain_id));
            public_data.eth_block.transactions.push(eth_tx);
        }

        let k = 16;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    }
}
