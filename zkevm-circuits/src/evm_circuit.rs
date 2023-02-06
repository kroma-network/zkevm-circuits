//! The EVM circuit implementation.

#![allow(missing_docs)]
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::*,
};

mod execution;
pub mod param;
pub(crate) mod step;
pub(crate) mod util;

pub mod table;

use crate::table::LookupTable;
pub use crate::witness;
use eth_types::Field;
use execution::ExecutionConfig;
use itertools::Itertools;
use table::FixedTableTag;
use witness::Block;

/// EvmCircuit implements verification of execution trace of a block.
#[derive(Clone, Debug)]
pub struct EvmCircuit<F> {
    fixed_table: [Column<Fixed>; 4],
    byte_table: [Column<Fixed>; 1],
    pub(crate) execution: Box<ExecutionConfig<F>>,
}

impl<F: Field> EvmCircuit<F> {
    /// Configure EvmCircuit
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        power_of_randomness: [Expression<F>; 31],
        tx_table: &dyn LookupTable<F>,
        rw_table: &dyn LookupTable<F>,
        bytecode_table: &dyn LookupTable<F>,
        block_table: &dyn LookupTable<F>,
        copy_table: &dyn LookupTable<F>,
        keccak_table: &dyn LookupTable<F>,
    ) -> Self {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());
        let byte_table = [(); 1].map(|_| meta.fixed_column());
        let execution = Box::new(ExecutionConfig::configure(
            meta,
            power_of_randomness,
            &fixed_table,
            &byte_table,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
        ));

        Self {
            fixed_table,
            byte_table,
            execution,
        }
    }

    /// Load fixed table
    pub fn load_fixed_table(
        &self,
        layouter: &mut impl Layouter<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                for (offset, row) in std::iter::once([F::zero(); 4])
                    .chain(fixed_table_tags.iter().flat_map(|tag| tag.build()))
                    .enumerate()
                {
                    for (column, value) in self.fixed_table.iter().zip_eq(row) {
                        region.assign_fixed(|| "", *column, offset, || Value::known(value))?;
                    }
                }

                Ok(())
            },
        )
    }

    /// Load byte table
    pub fn load_byte_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "byte table",
            |mut region| {
                for offset in 0..256 {
                    region.assign_fixed(
                        || "",
                        self.byte_table[0],
                        offset,
                        || Value::known(F::from(offset as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }

    /// Assign block
    pub fn assign_block(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        self.execution.assign_block(layouter, block, false)?;
        Ok(())
    }

    #[cfg(any(feature = "test", test))]
    /// Assign exact steps in block without padding for unit test purpose
    pub fn assign_block_exact(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        self.execution.assign_block(layouter, block, true)?;
        Ok(())
    }

    /// Calculate which rows are "actually" used in the circuit
    pub fn get_active_rows(&self, block: &Block<F>) -> (Vec<usize>, Vec<usize>) {
        let max_offset = self.get_num_rows_required(block);
        // some gates are enabled on all rows
        let gates_row_ids = (0..max_offset).collect();
        // lookups are enabled at "q_step" rows and byte lookup rows
        let lookup_row_ids = (0..max_offset).collect();
        (gates_row_ids, lookup_row_ids)
    }

    pub fn get_num_rows_required(&self, block: &Block<F>) -> usize {
        let mut num_rows = 0;
        for transaction in &block.txs {
            for step in &transaction.steps {
                num_rows += self.execution.get_step_height(step.execution_state);
            }
        }
        if num_rows == 0 {
            return 0;
        }
        // add 1 so we can be sure there is an unused `next` row available
        num_rows + 1
    }
}

#[cfg(any(feature = "test", test))]
pub mod test {
    use std::convert::TryInto;
    use strum::IntoEnumIterator;

    use crate::{
        evm_circuit::{table::FixedTableTag, witness::Block, EvmCircuit},
        table::{BlockTable, BytecodeTable, CopyTable, KeccakTable, RwTable, TxTable},
        util::DEFAULT_RAND,
    };
    use bus_mapping::evm::OpcodeId;
    use eth_types::{Field, Word};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, ConstraintSystem, Error, Expression},
    };
    use rand::{
        distributions::uniform::{SampleRange, SampleUniform},
        random, thread_rng, Rng,
    };

    pub(crate) fn rand_range<T, R>(range: R) -> T
    where
        T: SampleUniform,
        R: SampleRange<T>,
    {
        thread_rng().gen_range(range)
    }

    pub(crate) fn rand_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|_| random()).collect()
    }

    pub(crate) fn rand_bytes_array<const N: usize>() -> [u8; N] {
        [(); N].map(|_| random())
    }

    pub(crate) fn rand_word() -> Word {
        Word::from_big_endian(&rand_bytes_array::<32>())
    }

    /// create fixed_table_tags needed given witness block
    pub(crate) fn detect_fixed_table_tags<F: Field>(block: &Block<F>) -> Vec<FixedTableTag> {
        let need_bitwise_lookup = block.txs.iter().any(|tx| {
            tx.steps.iter().any(|step| {
                matches!(
                    step.opcode,
                    Some(OpcodeId::AND)
                        | Some(OpcodeId::OR)
                        | Some(OpcodeId::XOR)
                        | Some(OpcodeId::NOT)
                )
            })
        });
        FixedTableTag::iter()
            .filter(|t| {
                !matches!(
                    t,
                    FixedTableTag::BitwiseAnd
                        | FixedTableTag::BitwiseOr
                        | FixedTableTag::BitwiseXor
                ) || need_bitwise_lookup
            })
            .collect()
    }

    #[derive(Clone)]
    pub struct TestCircuitConfig<F> {
        tx_table: TxTable,
        rw_table: RwTable,
        bytecode_table: BytecodeTable,
        block_table: BlockTable,
        copy_table: CopyTable,
        keccak_table: KeccakTable,
        pub evm_circuit: EvmCircuit<F>,
    }

    #[derive(Default)]
    pub struct TestCircuit<F> {
        block: Block<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    }

    impl<F: Field> TestCircuit<F> {
        pub fn new(block: Block<F>, fixed_table_tags: Vec<FixedTableTag>) -> Self {
            Self {
                block,
                fixed_table_tags,
            }
        }
    }

    impl<F: Field> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let rw_table = RwTable::construct(meta);
            let tx_table = TxTable::construct(meta);
            let bytecode_table = BytecodeTable::construct(meta);
            let block_table = BlockTable::construct(meta);
            let q_copy_table = meta.fixed_column();
            let copy_table = CopyTable::construct(meta, q_copy_table);
            let keccak_table = KeccakTable::construct(meta);
            let power_of_randomness: [Expression<F>; 31] = (1..32)
                .map(|exp| Expression::Constant(F::from_u128(DEFAULT_RAND).pow(&[exp, 0, 0, 0])))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let evm_circuit = EvmCircuit::configure(
                meta,
                power_of_randomness,
                &tx_table,
                &rw_table,
                &bytecode_table,
                &block_table,
                &copy_table,
                &keccak_table,
            );

            Self::Config {
                tx_table,
                rw_table,
                bytecode_table,
                block_table,
                copy_table,
                keccak_table,
                evm_circuit,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config
                .evm_circuit
                .load_fixed_table(&mut layouter, self.fixed_table_tags.clone())?;
            config.evm_circuit.load_byte_table(&mut layouter)?;
            config
                .tx_table
                .load(&mut layouter, &self.block.txs, self.block.randomness)?;
            self.block.rws.check_rw_counter_sanity();
            config.rw_table.load(
                &mut layouter,
                &self.block.rws.table_assignments(),
                self.block.state_circuit_pad_to,
                self.block.randomness,
            )?;
            config.bytecode_table.load(
                &mut layouter,
                self.block.bytecodes.values(),
                self.block.randomness,
            )?;
            config.block_table.load(
                &mut layouter,
                &self.block.context,
                &self.block.txs,
                self.block.randomness,
            )?;
            config
                .copy_table
                .load(&mut layouter, &self.block, self.block.randomness)?;

            config.keccak_table.dev_load(
                &mut layouter,
                &self.block.sha3_inputs,
                self.block.randomness,
            )?;

            if self.block.evm_circuit_pad_to != 0 {
                config
                    .evm_circuit
                    .assign_block(&mut layouter, &self.block)?;
            } else {
                config
                    .evm_circuit
                    .assign_block_exact(&mut layouter, &self.block)?;
            }
            Ok(())
        }
    }

    impl<F: Field> TestCircuit<F> {
        pub fn get_num_rows_required(block: &Block<F>) -> usize {
            let mut cs = ConstraintSystem::default();
            let config = TestCircuit::configure(&mut cs);
            config.evm_circuit.get_num_rows_required(block)
        }

        pub fn get_active_rows(block: &Block<F>) -> (Vec<usize>, Vec<usize>) {
            let mut cs = ConstraintSystem::default();
            let config = TestCircuit::configure(&mut cs);
            config.evm_circuit.get_active_rows(block)
        }
    }

    pub fn run_test_circuit<F: Field>(block: Block<F>) -> Result<(), Vec<VerifyFailure>> {
        let fixed_table_tags = detect_fixed_table_tags(&block);
        let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;

        let num_rows_required_for_steps = TestCircuit::get_num_rows_required(&block);

        let k = log2_ceil(
            64 + fixed_table_tags
                .iter()
                .map(|tag| tag.build::<F>().count())
                .sum::<usize>(),
        );
        let k = k.max(log2_ceil(
            64 + block
                .bytecodes
                .values()
                .map(|bytecode| bytecode.bytes.len())
                .sum::<usize>(),
        ));
        let k = k.max(log2_ceil(64 + num_rows_required_for_steps));
        log::info!("evm circuit uses k = {}", k);
        let (active_gate_rows, active_lookup_rows) = TestCircuit::get_active_rows(&block);
        let circuit = TestCircuit::<F>::new(block, fixed_table_tags);
        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        prover.verify_at_rows_par(active_gate_rows.into_iter(), active_lookup_rows.into_iter())
    }
}

#[cfg(test)]
mod evm_circuit_stats {

    use super::test::*;
    use super::*;
    use crate::evm_circuit::step::ExecutionState;
    use eth_types::{bytecode, evm_types::OpcodeId, geth_types::GethData};
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::ConstraintSystem;
    use mock::{test_ctx::helpers::*, SimpleTestContext};
    use strum::IntoEnumIterator;

    #[test]
    pub fn empty_evm_circuit() {
        run_test_circuit(Block::<Fr>::default()).unwrap();
    }

    /// This function prints to stdout a table with all the implemented states
    /// and their responsible opcodes with the following stats:
    /// - height: number of rows in the EVM circuit used by the execution state
    /// - gas: gas value used for the opcode execution
    /// - height/gas: ratio between circuit cost and gas cost
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release get_evm_states_stats --
    /// --nocapture --ignored`
    #[ignore]
    #[test]
    pub fn get_evm_states_stats() {
        let mut meta = ConstraintSystem::<Fr>::default();
        let circuit = TestCircuit::configure(&mut meta);

        let mut implemented_states = Vec::new();
        for state in ExecutionState::iter() {
            let height = circuit.evm_circuit.execution.get_step_height_option(state);
            if let Some(h) = height {
                implemented_states.push((state, h));
            }
        }

        let mut stats = Vec::new();
        for (state, h) in implemented_states {
            for opcode in state.responsible_opcodes() {
                let mut code = bytecode! {
                    PUSH2(0x8000)
                    PUSH2(0x00)
                    PUSH2(0x10)
                    PUSH2(0x20)
                    PUSH2(0x30)
                    PUSH2(0x40)
                    PUSH2(0x50)
                };
                code.write_op(opcode);
                code.write_op(OpcodeId::STOP);
                let block: GethData = SimpleTestContext::new(
                    None,
                    account_0_code_account_1_no_code(code),
                    tx_from_1_to_0,
                    |block, _tx| block.number(0xcafeu64),
                )
                .unwrap()
                .into();
                let gas_cost = block.geth_traces[0].struct_logs[7].gas_cost.0;
                stats.push((state, opcode, h, gas_cost));
            }
        }

        println!(
            "| {: <14} | {: <14} | {: <2} | {: >6} | {: <5} |",
            "state", "opcode", "h", "g", "h/g"
        );
        println!("| ---            | ---            | ---|    --- | ---   |");
        for (state, opcode, height, gas_cost) in stats {
            println!(
                "| {: <14?} | {: <14?} | {: >2} | {: >6} | {: >1.3} |",
                state,
                opcode,
                height,
                gas_cost,
                height as f64 / gas_cost as f64
            );
        }
    }
}
