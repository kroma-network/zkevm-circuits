//! Public Input Circuit implementation

use std::io::Cursor;
use std::marker::PhantomData;

use eth_types::geth_types::BlockConstants;
use eth_types::geth_types::GethData;
use eth_types::H256;
use eth_types::{
    geth_types::Transaction, Address, Field, ToBigEndian, ToLittleEndian, ToScalar, Word,
};
use ethers_core::types::Block;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::plonk::Instance;

use crate::table::TxFieldTag;
use crate::tx_circuit::sign_verify::SignData;
use crate::tx_circuit::tx_to_sign_data;
use crate::util::random_linear_combine_word as rlc;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};

/// Fixed by the spec
const TX_LEN: usize = 9;
const BLOCK_LEN: usize = 7 + 256;
const EXTRA_LEN: usize = 2;

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
    nonce: Word,
    gas: Word, //gas limit
    gas_price: Word,
    from_addr: Address,
    to_addr: Address,
    is_create: u64,
    value: Word,
    call_data_len: u64,
    tx_sign_hash: [u8; 32],
}

/// Extra values (not contained in block or tx tables)
#[derive(Default, Debug, Clone)]
pub struct ExtraValues {
    // block_hash: H256,
    state_root: H256,
    prev_state_root: H256,
}

/// PublicData contains all the values that the PiCircuit recieves as input
#[derive(Debug, Clone)]
pub struct PublicData {
    /// List of tranactions
    pub txs: Vec<Transaction>,
    /// Information of Ethereum block
    pub extra: GethData,
    /// Constants related to Ethereum block
    pub block_constants: BlockConstants,
    /// Previous block root
    pub prev_state_root: H256,
}

impl Default for PublicData {
    fn default() -> Self {
        let geth_data = GethData {
            chain_id: Word::default(),
            history_hashes: Vec::default(),
            eth_block: Block::default(),
            geth_traces: Vec::default(),
            accounts: Vec::default(),
        };
        Self {
            txs: Vec::new(),
            extra: geth_data,
            block_constants: BlockConstants::default(),
            prev_state_root: H256::default(),
        }
    }
}

impl PublicData {
    /// Returns struct with values for the block table
    pub fn get_block_table_values(&self) -> BlockValues {
        let mut history_hashes: Vec<H256> = self
            .extra
            .history_hashes
            .iter()
            .map(|&hash| H256::from(hash.to_be_bytes()))
            .collect();
        history_hashes.extend(vec![H256::zero(); 256 - history_hashes.len()]);
        BlockValues {
            coinbase: self.block_constants.coinbase,
            gas_limit: self.block_constants.gas_limit.as_u64(),
            number: self.block_constants.number.as_u64(),
            timestamp: self.block_constants.timestamp.as_u64(),
            difficulty: self.block_constants.difficulty,
            base_fee: self.block_constants.base_fee,
            chain_id: self.extra.chain_id.as_u64(),
            history_hashes,
        }
    }

    /// Returns struct with values for the tx table
    pub fn get_tx_table_values(&self) -> Vec<TxValues> {
        let chain_id: u64 = self
            .extra
            .chain_id
            .try_into()
            .expect("Error converting chain_id to u64");
        let mut tx_vals = vec![];
        for tx in &self.txs {
            let sign_data: SignData =
                tx_to_sign_data(tx, chain_id).expect("Error computing tx_sign_hash");
            let mut msg_hash_le = [0u8; 32];
            sign_data
                .msg_hash
                .write(&mut Cursor::new(&mut msg_hash_le[..]))
                .expect("cannot write bytes to array");
            tx_vals.push(TxValues {
                nonce: tx.nonce,
                gas_price: tx.gas_price,
                gas: tx.gas_limit,
                from_addr: tx.from,
                to_addr: tx.to.unwrap_or_else(Address::zero),
                is_create: (tx.to.is_none() as u64),
                value: tx.value,
                call_data_len: tx.call_data.0.len() as u64,
                tx_sign_hash: msg_hash_le,
            });
        }
        tx_vals
    }

    /// Returns struct with the extra values
    pub fn get_extra_values(&self) -> ExtraValues {
        ExtraValues {
            // block_hash: self.extra.eth_block.hash.unwrap_or_else(H256::zero),
            state_root: self.extra.eth_block.state_root,
            prev_state_root: self.prev_state_root,
        }
    }
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    q_block_table: Selector,
    block_value: Column<Advice>,

    q_tx_table: Selector,
    tx_id: Column<Advice>,
    tag: Column<Fixed>,
    index: Column<Advice>,
    tx_value: Column<Advice>,

    raw_public_inputs: Column<Advice>,
    rpi_rlc_acc: Column<Advice>,
    rand_rpi: Column<Advice>,
    q_not_end: Selector,
    q_end: Selector,

    pi: Column<Instance>, // rpi_rand, rpi_rlc, chain_ID, state_root, prev_state_root

    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    PiCircuitConfig<F, MAX_TXS, MAX_CALLDATA>
{
    fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let q_block_table = meta.selector();
        // BlockTable
        let block_value = meta.advice_column();

        let q_tx_table = meta.selector();
        // Tx Table
        let tx_id = meta.advice_column();
        let tag = meta.fixed_column();
        let index = meta.advice_column();
        let tx_value = meta.advice_column();

        let raw_public_inputs = meta.advice_column();
        let rpi_rlc_acc = meta.advice_column();
        let rand_rpi = meta.advice_column();
        let q_not_end = meta.selector();
        let q_end = meta.selector();

        let pi = meta.instance_column();

        meta.enable_equality(raw_public_inputs);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(rand_rpi);
        meta.enable_equality(pi);

        // 0.0 rpi_rlc_acc[0] == RLC(raw_public_inputs, rand_rpi)
        meta.create_gate(
            "rpi_rlc_acc[i] = rand_rpi * rpi_rlc_acc[i+1] + raw_public_inputs[i] ",
            |meta| {
                // q_not_end * row.rpi_rlc_acc ==
                // (q_not_end * row_next.rpi_rlc_acc * row.rand_rpi + row.raw_public_inputs )
                let q_not_end = meta.query_selector(q_not_end);
                let cur_rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
                let next_rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::next());
                let rand_rpi = meta.query_advice(rand_rpi, Rotation::cur());
                let raw_public_inputs = meta.query_advice(raw_public_inputs, Rotation::cur());

                vec![
                    q_not_end * (next_rpi_rlc_acc * rand_rpi + raw_public_inputs - cur_rpi_rlc_acc),
                ]
            },
        );
        meta.create_gate("rpi_rlc_acc[last] = raw_public_inputs[last]", |meta| {
            let q_end = meta.query_selector(q_end);
            let raw_public_inputs = meta.query_advice(raw_public_inputs, Rotation::cur());
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            vec![q_end * (raw_public_inputs - rpi_rlc_acc)]
        });

        // 0.1 rand_rpi[i] == rand_rpi[j]
        meta.create_gate("rand_pi = rand_rpi.next", |meta| {
            // q_not_end * row.rand_rpi == q_not_end * row_next.rand_rpi
            let q_not_end = meta.query_selector(q_not_end);
            let cur_rand_rpi = meta.query_advice(rand_rpi, Rotation::cur());
            let next_rand_rpi = meta.query_advice(rand_rpi, Rotation::next());

            vec![q_not_end * (cur_rand_rpi - next_rand_rpi)]
        });

        // 0.2 Block table -> value column match with raw_public_inputs at expected
        // offset
        meta.create_gate("", |meta| {
            let q_block_table = meta.query_selector(q_block_table);
            let block_value = meta.query_advice(block_value, Rotation::cur());
            let rpi_block_value = meta.query_advice(raw_public_inputs, Rotation::cur());
            vec![q_block_table * (block_value - rpi_block_value)]
        });

        let offset = BLOCK_LEN + 1 + EXTRA_LEN;
        let tx_table_len = MAX_TXS * TX_LEN + 1 + MAX_CALLDATA;

        //  0.3 Tx table -> {tx_id, index, value} column match with raw_public_inputs
        // at expected offset
        meta.create_gate(
            "tx_table.tx_id[i] == raw_public_inputs[offset + i]",
            |meta| {
                // row.q_tx_table * row.tx_table.tx_id
                // == row.q_tx_table * row_offset_tx_table_tx_id.raw_public_inputs
                let q_tx_table = meta.query_selector(q_tx_table);
                let tx_id = meta.query_advice(tx_id, Rotation::cur());
                let rpi_tx_id = meta.query_advice(raw_public_inputs, Rotation(offset as i32));

                vec![q_tx_table * (tx_id - rpi_tx_id)]
            },
        );

        meta.create_gate(
            "tx_table.index[i] == raw_public_inputs[offset + tx_table_len + i]",
            |meta| {
                // row.q_tx_table * row.tx_table.tx_index
                // == row.q_tx_table * row_offset_tx_table_tx_index.raw_public_inputs
                let q_tx_table = meta.query_selector(q_tx_table);
                let tx_index = meta.query_advice(index, Rotation::cur());
                let rpi_tx_index =
                    meta.query_advice(raw_public_inputs, Rotation((offset + tx_table_len) as i32));

                vec![q_tx_table * (tx_index - rpi_tx_index)]
            },
        );

        meta.create_gate(
            "tx_table.tx_value[i] == raw_public_inputs[offset + 2* tx_table_len + i]",
            |meta| {
                // row.q_tx_table * row.tx_table.tx_value
                // == row.q_tx_table * row_offset_tx_table_tx_value.raw_public_inputs
                let q_tx_table = meta.query_selector(q_tx_table);
                let tx_value = meta.query_advice(tx_value, Rotation::cur());
                let rpi_tx_value = meta.query_advice(
                    raw_public_inputs,
                    Rotation((offset + 2 * tx_table_len) as i32),
                );

                vec![q_tx_table * (tx_value - rpi_tx_value)]
            },
        );

        Self {
            q_block_table,
            block_value,
            q_tx_table,
            tx_id,
            tag,
            index,
            tx_value,
            raw_public_inputs,
            rpi_rlc_acc,
            rand_rpi,
            q_not_end,
            q_end,
            pi,
            _marker: PhantomData,
        }
    }

    /// Return the number of rows in the circuit
    #[inline]
    fn circuit_len() -> usize {
        // +1 empty row in block table, +1 empty row in tx_table
        BLOCK_LEN + 1 + EXTRA_LEN + 3 * (TX_LEN * MAX_TXS + 1 + MAX_CALLDATA)
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
        raw_pi_vals: &mut [F],
    ) -> Result<(), Error> {
        let tx_id = F::from(tx_id as u64);
        let tag = F::from(tag as u64);
        let index = F::from(index as u64);
        let tx_value = tx_value;

        self.q_tx_table.enable(region, offset)?;

        // Assign vals to Tx_table
        region.assign_advice(|| "tx_id", self.tx_id, offset, || Ok(tx_id))?;
        region.assign_fixed(|| "tag", self.tag, offset, || Ok(tag))?;
        region.assign_advice(|| "index", self.index, offset, || Ok(index))?;
        region.assign_advice(|| "tx_value", self.tx_value, offset, || Ok(tx_value))?;

        // Assign vals to raw_public_inputs column
        let tx_table_len = TX_LEN * MAX_TXS + 1 + MAX_CALLDATA;

        let id_offset = BLOCK_LEN + 1 + EXTRA_LEN;
        let index_offset = id_offset + tx_table_len;
        let value_offset = index_offset + tx_table_len;

        region.assign_advice(
            || "raw_pi.tx_id",
            self.raw_public_inputs,
            offset + id_offset,
            || Ok(tx_id),
        )?;

        region.assign_advice(
            || "raw_pi.tx_index",
            self.raw_public_inputs,
            offset + index_offset,
            || Ok(index),
        )?;

        region.assign_advice(
            || "raw_pi.tx_value",
            self.raw_public_inputs,
            offset + value_offset,
            || Ok(tx_value),
        )?;

        // Add copy to vec
        raw_pi_vals[offset + id_offset] = tx_id;
        raw_pi_vals[offset + index_offset] = index;
        raw_pi_vals[offset + value_offset] = tx_value;

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
        raw_pi_vals: &mut [F],
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut offset = 0;
        for i in 0..BLOCK_LEN + 1 {
            self.q_block_table.enable(region, offset + i)?;
        }

        // zero row
        region.assign_advice(|| "zero", self.block_value, offset, || Ok(F::zero()))?;
        region.assign_advice(|| "zero", self.raw_public_inputs, offset, || Ok(F::zero()))?;
        raw_pi_vals[offset] = F::zero();
        offset += 1;

        // coinbase
        let coinbase = block_values.coinbase.to_scalar().unwrap();
        region.assign_advice(|| "coinbase", self.block_value, offset, || Ok(coinbase))?;
        region.assign_advice(
            || "coinbase",
            self.raw_public_inputs,
            offset,
            || Ok(coinbase),
        )?;
        raw_pi_vals[offset] = coinbase;
        offset += 1;

        // gas_limit
        let gas_limit = F::from(block_values.gas_limit);
        region.assign_advice(|| "gas_limit", self.block_value, offset, || Ok(gas_limit))?;
        region.assign_advice(
            || "gas_limit",
            self.raw_public_inputs,
            offset,
            || Ok(gas_limit),
        )?;
        raw_pi_vals[offset] = gas_limit;
        offset += 1;

        // number
        let number = F::from(block_values.number);
        region.assign_advice(|| "number", self.block_value, offset, || Ok(number))?;
        region.assign_advice(|| "number", self.raw_public_inputs, offset, || Ok(number))?;
        raw_pi_vals[offset] = number;
        offset += 1;

        // timestamp
        let timestamp = F::from(block_values.timestamp);
        region.assign_advice(|| "timestamp", self.block_value, offset, || Ok(timestamp))?;
        region.assign_advice(
            || "timestamp",
            self.raw_public_inputs,
            offset,
            || Ok(timestamp),
        )?;
        raw_pi_vals[offset] = timestamp;
        offset += 1;

        // difficulty
        let difficulty = rlc(block_values.difficulty.to_le_bytes(), randomness);
        region.assign_advice(|| "difficulty", self.block_value, offset, || Ok(difficulty))?;
        region.assign_advice(
            || "difficulty",
            self.raw_public_inputs,
            offset,
            || Ok(difficulty),
        )?;
        raw_pi_vals[offset] = difficulty;
        offset += 1;

        // base_fee
        let base_fee = rlc(block_values.base_fee.to_le_bytes(), randomness);
        region.assign_advice(|| "base_fee", self.block_value, offset, || Ok(base_fee))?;
        region.assign_advice(
            || "base_fee",
            self.raw_public_inputs,
            offset,
            || Ok(base_fee),
        )?;
        raw_pi_vals[offset] = base_fee;
        offset += 1;

        // chain_id
        let chain_id = F::from(block_values.chain_id);
        region.assign_advice(|| "chain_id", self.block_value, offset, || Ok(chain_id))?;
        let chain_id_cell = region.assign_advice(
            || "chain_id",
            self.raw_public_inputs,
            offset,
            || Ok(chain_id),
        )?;
        raw_pi_vals[offset] = chain_id;
        offset += 1;

        for prev_hash in block_values.history_hashes {
            let prev_hash = rlc(prev_hash.to_fixed_bytes(), randomness);
            region.assign_advice(|| "prev_hash", self.block_value, offset, || Ok(prev_hash))?;
            region.assign_advice(
                || "prev_hash",
                self.raw_public_inputs,
                offset,
                || Ok(prev_hash),
            )?;
            raw_pi_vals[offset] = prev_hash;
            offset += 1;
        }

        Ok(chain_id_cell)
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
        raw_pi_vals: &mut [F],
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
            || Ok(state_root),
        )?;
        raw_pi_vals[offset] = state_root;
        offset += 1;

        // previous block state root
        let prev_state_root = rlc(extra.prev_state_root.to_fixed_bytes(), randomness);
        let prev_state_root_cell = region.assign_advice(
            || "parent_block.hash",
            self.raw_public_inputs,
            offset,
            || Ok(prev_state_root),
        )?;
        raw_pi_vals[offset] = prev_state_root;
        Ok([state_root_cell, prev_state_root_cell])
    }

    /// Assign `rpi_rlc_acc` and `rand_rpi` columns
    #[allow(clippy::type_complexity)]
    fn assign_rlc_pi(
        &self,
        region: &mut Region<'_, F>,
        rand_rpi: F,
        raw_pi_vals: Vec<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let circuit_len = Self::circuit_len();
        assert_eq!(circuit_len, raw_pi_vals.len());

        // Last row
        let offset = circuit_len - 1;
        let mut rpi_rlc_acc = raw_pi_vals[offset];
        region.assign_advice(
            || "rpi_rlc_acc",
            self.rpi_rlc_acc,
            offset,
            || Ok(rpi_rlc_acc),
        )?;
        region.assign_advice(|| "rand_rpi", self.rand_rpi, offset, || Ok(rand_rpi))?;
        self.q_end.enable(region, offset)?;

        // Next rows
        for offset in (1..circuit_len - 1).rev() {
            rpi_rlc_acc *= rand_rpi;
            rpi_rlc_acc += raw_pi_vals[offset];
            region.assign_advice(
                || "rpi_rlc_acc",
                self.rpi_rlc_acc,
                offset,
                || Ok(rpi_rlc_acc),
            )?;
            region.assign_advice(|| "rand_rpi", self.rand_rpi, offset, || Ok(rand_rpi))?;
            self.q_not_end.enable(region, offset)?;
        }

        // First row
        rpi_rlc_acc *= rand_rpi;
        rpi_rlc_acc += raw_pi_vals[0];
        let rpi_rlc =
            region.assign_advice(|| "rpi_rlc_acc", self.rpi_rlc_acc, 0, || Ok(rpi_rlc_acc))?;
        let rpi_rand = region.assign_advice(|| "rand_rpi", self.rand_rpi, 0, || Ok(rand_rpi))?;
        self.q_not_end.enable(region, 0)?;
        Ok((rpi_rand, rpi_rlc))
    }
}

/// Public Inputs Circuit
#[derive(Default)]
pub struct PiCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    /// Randomness for RLC encdoing
    pub randomness: F,

    /// Randomness for PI encoding
    pub rand_rpi: F,

    /// PublicInputs data known by the verifier
    pub public_data: PublicData,
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
        PiCircuitConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let pi_cells = layouter.assign_region(
            || "region 0",
            |mut region| {
                let circuit_len = Self::Config::circuit_len();
                let mut raw_pi_vals = vec![F::zero(); circuit_len];

                // Assign block table
                let block_values = self.public_data.get_block_table_values();
                let chain_id = config.assign_block_table(
                    &mut region,
                    block_values,
                    self.randomness,
                    &mut raw_pi_vals,
                )?;

                // Assign extra fields
                let extra_vals = self.public_data.get_extra_values();
                let [state_root, prev_state_root] = config.assign_extra_fields(
                    &mut region,
                    extra_vals,
                    self.randomness,
                    &mut raw_pi_vals,
                )?;

                let mut offset = 0;
                // Assign Tx table
                let txs = self.public_data.get_tx_table_values();
                assert!(txs.len() <= MAX_TXS);
                let tx_default = TxValues::default();

                // Add empty row
                config.assign_tx_row(
                    &mut region,
                    offset,
                    0,
                    TxFieldTag::Null,
                    0,
                    F::zero(),
                    &mut raw_pi_vals,
                )?;
                offset += 1;

                for i in 0..MAX_TXS {
                    let tx = if i < txs.len() { &txs[i] } else { &tx_default };

                    for (tag, value) in &[
                        (
                            TxFieldTag::Nonce,
                            rlc(tx.nonce.to_le_bytes(), self.randomness),
                        ),
                        (TxFieldTag::Gas, rlc(tx.gas.to_le_bytes(), self.randomness)),
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
                        (
                            TxFieldTag::TxSignHash,
                            rlc(tx.tx_sign_hash, self.randomness),
                        ),
                    ] {
                        config.assign_tx_row(
                            &mut region,
                            offset,
                            i + 1,
                            *tag,
                            0,
                            *value,
                            &mut raw_pi_vals,
                        )?;
                        offset += 1;
                    }
                }
                // Tx Table CallData
                let mut calldata_count = 0;
                for (i, tx) in self.public_data.txs.iter().enumerate() {
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < MAX_CALLDATA);
                        config.assign_tx_row(
                            &mut region,
                            offset,
                            i + 1,
                            TxFieldTag::CallData,
                            index,
                            F::from(*byte as u64),
                            &mut raw_pi_vals,
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
                        &mut raw_pi_vals,
                    )?;
                    offset += 1;
                }

                // rpi_rlc and rand_rpi cols
                let (rpi_rand, rpi_rlc) =
                    config.assign_rlc_pi(&mut region, self.rand_rpi, raw_pi_vals)?;

                Ok(vec![
                    rpi_rand,
                    rpi_rlc,
                    chain_id,
                    state_root,
                    prev_state_root,
                ])
            },
        )?;

        // Constrain raw_public_input cells to public inputs
        for (i, pi_cell) in pi_cells.iter().enumerate() {
            layouter.constrain_instance(pi_cell.cell(), config.pi, i)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod pi_circuit_test {
    use super::*;

    use crate::test_util::rand_tx;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        pairing::bn256::Fr,
    };
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Compute the raw_public_inputs column from the verifier's perspective.
    fn raw_public_inputs_col<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        public_data: &PublicData,
        randomness: F, // For RLC encoding
    ) -> Vec<F> {
        let block = public_data.get_block_table_values();
        let extra = public_data.get_extra_values();
        let txs = public_data.get_tx_table_values();

        let mut offset = 0;
        let mut result =
            vec![F::zero(); BLOCK_LEN + 1 + EXTRA_LEN + 3 * (TX_LEN * MAX_TXS + 1 + MAX_CALLDATA)];

        //  Insert Block Values
        // zero row
        result[offset] = F::zero();
        offset += 1;
        // coinbase
        let mut coinbase_bytes = [0u8; 32];
        coinbase_bytes[12..].clone_from_slice(block.coinbase.as_bytes());
        result[offset] = rlc(coinbase_bytes, randomness);
        offset += 1;
        // gas_limit
        result[offset] = F::from(block.gas_limit);
        offset += 1;
        // number
        result[offset] = F::from(block.number);
        offset += 1;
        // timestamp
        result[offset] = F::from(block.timestamp);
        offset += 1;
        // difficulty
        result[offset] = rlc(block.difficulty.to_le_bytes(), randomness);
        offset += 1;
        // base_fee
        result[offset] = rlc(block.base_fee.to_le_bytes(), randomness);
        offset += 1;
        // chain_id
        result[offset] = F::from(block.chain_id);
        offset += 1;
        // Previous block hashes
        for prev_hash in block.history_hashes {
            result[offset] = rlc(prev_hash.to_fixed_bytes(), randomness);
            offset += 1;
        }

        // Insert Extra Values
        // block Root
        result[BLOCK_LEN] = rlc(extra.state_root.to_fixed_bytes(), randomness);
        // parent block hash
        result[BLOCK_LEN + 1] = rlc(extra.prev_state_root.to_fixed_bytes(), randomness);

        // Insert Tx table
        offset = 0;
        assert!(txs.len() < MAX_TXS);
        let tx_default = TxValues::default();

        let tx_table_len = TX_LEN * MAX_TXS + 1 + MAX_CALLDATA;

        let id_offset = BLOCK_LEN + 1 + EXTRA_LEN;
        let index_offset = id_offset + tx_table_len;
        let value_offset = index_offset + tx_table_len;

        // Insert zero row
        result[id_offset + offset] = F::zero();
        result[index_offset + offset] = F::zero();
        result[value_offset + offset] = F::zero();

        offset += 1;

        for i in 0..MAX_TXS {
            let tx = if i < txs.len() { &txs[i] } else { &tx_default };

            for val in &[
                rlc(tx.nonce.to_le_bytes(), randomness),
                rlc(tx.gas.to_le_bytes(), randomness),
                rlc(tx.gas_price.to_le_bytes(), randomness),
                tx.from_addr.to_scalar().expect("tx.from too big"),
                tx.to_addr.to_scalar().expect("tx.to too big"),
                F::from(tx.is_create),
                rlc(tx.value.to_le_bytes(), randomness),
                F::from(tx.call_data_len),
                rlc(tx.tx_sign_hash, randomness),
            ] {
                result[id_offset + offset] = F::from((i + 1) as u64);
                result[index_offset + offset] = F::zero();
                result[value_offset + offset] = *val;

                offset += 1;
            }
        }
        // Tx Table CallData
        let mut calldata_count = 0;
        for (i, tx) in public_data.txs.iter().enumerate() {
            for (index, byte) in tx.call_data.0.iter().enumerate() {
                assert!(calldata_count < MAX_CALLDATA);
                result[id_offset + offset] = F::from((i + 1) as u64);
                result[index_offset + offset] = F::from(index as u64);
                result[value_offset + offset] = F::from(*byte as u64);
                offset += 1;
                calldata_count += 1;
            }
        }
        for _ in calldata_count..MAX_CALLDATA {
            result[id_offset + offset] = F::zero();
            result[index_offset + offset] = F::zero();
            result[value_offset + offset] = F::zero();
            offset += 1;
        }

        result
    }

    fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        k: u32,
        public_data: PublicData,
    ) -> Result<(), Vec<VerifyFailure>> {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let randomness = F::random(&mut rng);

        let rand_rpi = F::random(&mut rng);
        let rlc_rpi_col =
            raw_public_inputs_col::<F, MAX_TXS, MAX_CALLDATA>(&public_data, randomness);
        assert_eq!(
            rlc_rpi_col.len(),
            BLOCK_LEN + 1 + EXTRA_LEN + 3 * (TX_LEN * MAX_TXS + 1 + MAX_CALLDATA)
        );

        // Computation of raw_pulic_inputs
        let rlc_rpi = rlc_rpi_col
            .iter()
            .rev()
            .fold(F::zero(), |acc, val| acc * rand_rpi + val);

        // let block_hash = public_data
        //     .extra
        //     .eth_block
        //     .hash
        //     .unwrap_or_else(H256::zero)
        //     .to_fixed_bytes();

        let public_inputs = vec![
            rand_rpi,
            rlc_rpi,
            F::from(public_data.extra.chain_id.as_u64()),
            rlc(
                public_data.extra.eth_block.state_root.to_fixed_bytes(),
                randomness,
            ),
            rlc(public_data.prev_state_root.to_fixed_bytes(), randomness),
        ];

        let circuit = PiCircuit::<F, MAX_TXS, MAX_CALLDATA> {
            randomness,
            rand_rpi,
            public_data,
        };

        let prover = match MockProver::run(k, &circuit, vec![public_inputs]) {
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

        let k = 13;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    }

    #[test]
    fn test_simple_pi() {
        const MAX_TXS: usize = 4;
        const MAX_CALLDATA: usize = 20;

        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let mut public_data = PublicData::default();
        let chain_id = 1337u64;
        public_data.extra.chain_id = Word::from(chain_id);

        let n_tx = 2;
        for _ in 0..n_tx {
            public_data.txs.push(rand_tx(&mut rng, chain_id));
        }

        let k = 13;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    }
}
