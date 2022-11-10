//! The transaction circuit implementation.

// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

pub mod sign_verify;

use crate::table::{KeccakTable, LookupTable, RlpTable, TxFieldTag, TxTable};
use crate::util::{random_linear_combine_word as rlc, Challenges};
use crate::witness::{signed_tx_from_geth_tx, RlpDataType};
use bus_mapping::circuit_input_builder::keccak_inputs_tx_circuit;
use eth_types::{
    sign_types::SignData,
    {geth_types::Transaction, Address, Field, ToLittleEndian, ToScalar},
};
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::util::{and, Expr};
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use log::error;
use sign_verify::{SignVerifyChip, SignVerifyConfig};
use std::marker::PhantomData;

pub use halo2_proofs::halo2curves::{
    group::{
        ff::{Field as GroupField, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group, GroupEncoding,
    },
    secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
};

/// Config for TxCircuit
#[derive(Clone, Debug)]
pub struct TxCircuitConfig<F: Field> {
    q_enable: Column<Fixed>,
    tx_id: Column<Advice>,
    tag: BinaryNumberConfig<TxFieldTag, 4>,
    index: Column<Advice>,
    value: Column<Advice>,
    sign_verify: SignVerifyConfig,
    keccak_table: KeccakTable,
    rlp_table: RlpTable,
    _marker: PhantomData<F>,
}

impl<F: Field> TxCircuitConfig<F> {
    /// Return a new TxCircuitConfig
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        tx_table: TxTable,
        keccak_table: KeccakTable,
        rlp_table: RlpTable,
        challenges: Challenges<Expression<F>>,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let tx_id = tx_table.tx_id;
        let tag = BinaryNumberChip::configure(meta, q_enable, None);
        let index = tx_table.index;
        let value = tx_table.value;
        meta.enable_equality(value);

        Self::configure_lookups(meta, q_enable, tag, rlp_table, tx_table);

        let sign_verify = SignVerifyConfig::new(meta, keccak_table.clone(), challenges);

        Self {
            q_enable,
            tx_id,
            tag,
            index,
            value,
            sign_verify,
            keccak_table,
            rlp_table,
            _marker: PhantomData,
        }
    }

    /// Load ECDSA RangeChip table.
    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.sign_verify.load_range(layouter)
    }

    /// Assigns a tx circuit row and returns the assigned cell of the value in
    /// the row.
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tag: TxFieldTag,
        index: usize,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_fixed(
            || "q_enable",
            self.q_enable,
            offset,
            || Value::known(F::one()),
        )?;
        region.assign_advice(
            || "tx_id",
            self.tx_id,
            offset,
            || Value::known(F::from(tx_id as u64)),
        )?;

        let tag_chip = BinaryNumberChip::construct(self.tag);
        tag_chip.assign(region, offset, &tag)?;

        region.assign_advice(
            || "index",
            self.index,
            offset,
            || Value::known(F::from(index as u64)),
        )?;
        region.assign_advice(|| "value", self.value, offset, || value)
    }

    /// Get number of rows required.
    pub fn get_num_rows_required(num_tx: usize) -> usize {
        let num_rows_range_table = 1 << 18;
        // Number of rows required to verify a transaction.
        let num_rows_per_tx = 140436;
        (num_tx * num_rows_per_tx).max(num_rows_range_table)
    }

    fn configure_lookups(
        meta: &mut ConstraintSystem<F>,
        q_enable: Column<Fixed>,
        tag: BinaryNumberConfig<TxFieldTag, 4>,
        rlp_table: RlpTable,
        tx_table: TxTable,
    ) {
        // lookup tx nonce.
        meta.lookup_any("tx nonce in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Nonce, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::Nonce.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx nonce in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Nonce, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::Nonce.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx rlc(gasprice).
        meta.lookup_any("tx rlc(gasprice) in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::GasPrice, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::GasPrice.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx rlc(gasprice) in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::GasPrice, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::GasPrice.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx gas.
        meta.lookup_any("tx gas in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Gas, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::Gas.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx gas in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Gas, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::Gas.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx callee address.
        meta.lookup_any("tx callee address in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CalleeAddress, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::CalleeAddress.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx callee address in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CalleeAddress, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::CalleeAddress.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx rlc(value).
        meta.lookup_any("tx rlc(value) in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Value, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::Value.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx rlc(value) in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Value, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::Value.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx rlc(calldata).
        meta.lookup_any("tx rlc(calldata) in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CallDataRlc, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::CallDataRlc.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx rlc(calldata) in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CallDataRlc, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::CallDataRlc.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
    }
}

/// Tx Circuit for verifying transaction signatures
#[derive(Clone, Default, Debug)]
pub struct TxCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    /// SignVerify chip
    pub sign_verify: SignVerifyChip<F, MAX_TXS>,
    /// List of Transactions
    pub txs: Vec<Transaction>,
    /// Chain ID
    pub chain_id: u64,
    /// Randomness.
    pub randomness: F,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    TxCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    /// Return a new TxCircuit
    pub fn new(
        aux_generator: Secp256k1Affine,
        chain_id: u64,
        txs: Vec<Transaction>,
        randomness: F,
    ) -> Self {
        TxCircuit::<F, MAX_TXS, MAX_CALLDATA> {
            sign_verify: SignVerifyChip {
                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            },
            txs,
            chain_id,
            randomness,
        }
    }

    /// Make the assignments to the TxCircuit
    pub fn assign(
        &self,
        config: &TxCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        assert!(self.txs.len() <= MAX_TXS);
        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .map(|tx| {
                tx.sign_data(self.chain_id).map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", e);
                    Error::Synthesis
                })
            })
            .try_collect()?;

        let assigned_sig_verifs =
            self.sign_verify
                .assign(&config.sign_verify, layouter, &sign_datas, challenges)?;

        layouter.assign_region(
            || "tx table",
            |mut region| {
                let mut offset = 0;
                // Empty entry
                config.assign_row(
                    &mut region,
                    offset,
                    0,
                    TxFieldTag::Null,
                    0,
                    Value::known(F::zero()),
                )?;
                offset += 1;
                // Assign al Tx fields except for call data
                let tx_default = Transaction::default();
                for (i, assigned_sig_verif) in assigned_sig_verifs.iter().enumerate() {
                    let tx = if i < self.txs.len() {
                        &self.txs[i]
                    } else {
                        &tx_default
                    };

                    for (tag, value) in [
                        (TxFieldTag::Nonce, Value::known(F::from(tx.nonce.as_u64()))),
                        (
                            TxFieldTag::Gas,
                            Value::known(F::from(tx.gas_limit.as_u64())),
                        ),
                        (
                            TxFieldTag::GasPrice,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.gas_price.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::CallerAddress,
                            Value::known(tx.from.to_scalar().expect("tx.from too big")),
                        ),
                        (
                            TxFieldTag::CalleeAddress,
                            Value::known(
                                tx.to
                                    .unwrap_or_else(Address::zero)
                                    .to_scalar()
                                    .expect("tx.to too big"),
                            ),
                        ),
                        (
                            TxFieldTag::IsCreate,
                            Value::known(F::from(tx.to.is_none() as u64)),
                        ),
                        (
                            TxFieldTag::Value,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.value.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::CallDataLength,
                            Value::known(F::from(tx.call_data.0.len() as u64)),
                        ),
                        (
                            TxFieldTag::CallDataGasCost,
                            Value::known(F::from(
                                tx.call_data
                                    .0
                                    .iter()
                                    .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
                            )),
                        ),
                        (
                            TxFieldTag::TxSignHash,
                            assigned_sig_verif.msg_hash_rlc.value().copied(),
                        ),
                    ] {
                        let assigned_cell =
                            config.assign_row(&mut region, offset, i + 1, tag, 0, value)?;
                        offset += 1;

                        // Ref. spec 0. Copy constraints using fixed offsets between the tx rows and
                        // the SignVerifyChip
                        match tag {
                            TxFieldTag::CallerAddress => region.constrain_equal(
                                assigned_cell.cell(),
                                assigned_sig_verif.address.cell(),
                            )?,
                            TxFieldTag::TxSignHash => region.constrain_equal(
                                assigned_cell.cell(),
                                assigned_sig_verif.msg_hash_rlc.cell(),
                            )?,
                            _ => (),
                        }
                    }
                }

                // Assign call data
                let mut calldata_count = 0;
                for (i, tx) in self.txs.iter().enumerate() {
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < MAX_CALLDATA);
                        config.assign_row(
                            &mut region,
                            offset,
                            i + 1, // tx_id
                            TxFieldTag::CallData,
                            index,
                            Value::known(F::from(*byte as u64)),
                        )?;
                        offset += 1;
                        calldata_count += 1;
                    }
                }
                for _ in calldata_count..MAX_CALLDATA {
                    config.assign_row(
                        &mut region,
                        offset,
                        0, // tx_id
                        TxFieldTag::CallData,
                        0,
                        Value::known(F::zero()),
                    )?;
                    offset += 1;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn get_randomness() -> F {
        F::from(123456789u64)
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for TxCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = (TxCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let rlp_table = RlpTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            TxCircuitConfig::new(meta, tx_table, keccak_table, rlp_table, challenges)
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);

        config.load(&mut layouter)?;
        self.assign(&config, &mut layouter, &challenges)?;
        config.keccak_table.dev_load(
            &mut layouter,
            &keccak_inputs_tx_circuit(&self.txs[..], self.chain_id).map_err(|e| {
                error!("keccak_inputs_tx_circuit error: {:?}", e);
                Error::Synthesis
            })?,
            &challenges,
        )?;
        config.rlp_table.dev_load(
            &mut layouter,
            signed_tx_from_geth_tx(self.txs.as_slice(), self.chain_id),
            self.randomness,
        )
    }
}

#[cfg(test)]
mod tx_circuit_tests {
    use super::*;
    use eth_types::address;
    use halo2_proofs::{
        arithmetic::CurveAffine,
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, group::Group},
    };
    use mock::AddrOrWallet;
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        k: u32,
        txs: Vec<Transaction>,
        chain_id: u64,
    ) -> Result<(), Vec<VerifyFailure>> {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let aux_generator =
            <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();

        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        let circuit = TxCircuit::<F, MAX_TXS, MAX_CALLDATA> {
            sign_verify: SignVerifyChip {
                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            },
            txs,
            chain_id,
            randomness: TxCircuit::<F, MAX_TXS, MAX_CALLDATA>::get_randomness(),
        };

        let prover = match MockProver::run(k, &circuit, vec![vec![]]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    #[test]
    fn tx_circuit_2tx() {
        const NUM_TXS: usize = 2;
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;

        let k = 19;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(
                k,
                mock::CORRECT_MOCK_TXS[..NUM_TXS]
                    .iter()
                    .map(|tx| Transaction::from(tx.clone()))
                    .collect_vec(),
                mock::MOCK_CHAIN_ID.as_u64()
            ),
            Ok(())
        );
    }

    #[test]
    fn tx_circuit_1tx() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

        let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

        let k = 19;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, vec![tx], chain_id),
            Ok(())
        );
    }

    #[test]
    fn tx_circuit_bad_address() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let mut tx = mock::CORRECT_MOCK_TXS[0].clone();
        // This address doesn't correspond to the account that signed this tx.
        tx.from = AddrOrWallet::from(address!("0x1230000000000000000000000000000000000456"));

        let k = 19;
        assert!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, vec![tx.into()], mock::MOCK_CHAIN_ID.as_u64())
                .is_err(),
        );
    }
}
