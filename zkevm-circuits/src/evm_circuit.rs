//! The EVM circuit implementation.

#![allow(missing_docs)]
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Expression, Fixed},
};

mod execution;
pub mod param;
pub(crate) mod step;
pub(crate) mod util;

pub mod table;

pub use crate::witness;
use crate::{
    table::{
        BlockTable, BytecodeTable, CopyTable, ExpTable, KeccakTable, LookupTable, RwTable, TxTable,
    },
    util::{SubCircuit, SubCircuitConfig},
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use execution::ExecutionConfig;
use itertools::Itertools;
use strum::IntoEnumIterator;
use table::FixedTableTag;
use witness::Block;

/// EvmCircuitConfig implements verification of execution trace of a block.
#[derive(Clone, Debug)]
pub struct EvmCircuitConfig<F> {
    fixed_table: [Column<Fixed>; 4],
    byte_table: [Column<Fixed>; 1],
    pub(crate) execution: Box<ExecutionConfig<F>>,
    // External tables
    tx_table: TxTable,
    rw_table: RwTable,
    bytecode_table: BytecodeTable,
    block_table: BlockTable,
    copy_table: CopyTable,
    keccak_table: KeccakTable,
    exp_table: ExpTable,
}

/// Circuit configuration arguments
pub struct EvmCircuitConfigArgs<F: Field> {
    /// Challenge
    pub challenges: crate::util::Challenges<Expression<F>>,
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// CopyTable
    pub copy_table: CopyTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// ExpTable
    pub exp_table: ExpTable,
}

impl<F: Field> SubCircuitConfig<F> for EvmCircuitConfig<F> {
    type ConfigArgs = EvmCircuitConfigArgs<F>;

    /// Configure EvmCircuitConfig
    #[allow(clippy::too_many_arguments)]
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            challenges,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());
        let byte_table = [(); 1].map(|_| meta.fixed_column());
        let execution = Box::new(ExecutionConfig::configure(
            meta,
            challenges,
            &fixed_table,
            &byte_table,
            &tx_table,
            &rw_table,
            &bytecode_table,
            &block_table,
            &copy_table,
            &keccak_table,
            &exp_table,
        ));

        meta.annotate_lookup_any_column(byte_table[0], || "byte_range");
        fixed_table.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_any_column(col, || format!("fix_table_{idx}"))
        });
        tx_table.annotate_columns(meta);
        rw_table.annotate_columns(meta);
        bytecode_table.annotate_columns(meta);
        block_table.annotate_columns(meta);
        copy_table.annotate_columns(meta);
        keccak_table.annotate_columns(meta);
        exp_table.annotate_columns(meta);

        Self {
            fixed_table,
            byte_table,
            execution,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
        }
    }
}

impl<F: Field> EvmCircuitConfig<F> {
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
}

/// Tx Circuit for verifying transaction signatures
#[derive(Clone, Default, Debug)]
pub struct EvmCircuit<F: Field> {
    /// Block
    pub block: Option<Block<F>>,
    fixed_table_tags: Vec<FixedTableTag>,
}

impl<F: Field> EvmCircuit<F> {
    /// Return a new EvmCircuit
    pub fn new(block: Block<F>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags: FixedTableTag::iter().collect(),
        }
    }

    pub fn new_dev(block: Block<F>, fixed_table_tags: Vec<FixedTableTag>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags,
        }
    }

    /// Calculate which rows are "actually" used in the circuit
    pub fn get_active_rows(block: &Block<F>) -> (Vec<usize>, Vec<usize>) {
        let max_offset = Self::get_num_rows_required(block);
        // some gates are enabled on all rows
        let gates_row_ids = (0..max_offset).collect();
        // lookups are enabled at "q_step" rows and byte lookup rows
        let lookup_row_ids = (0..max_offset).collect();
        (gates_row_ids, lookup_row_ids)
    }

    pub fn get_num_rows_required_no_padding(block: &Block<F>) -> usize {
        // Start at 1 so we can be sure there is an unused `next` row available
        let mut num_rows = 1;
        for transaction in &block.txs {
            for step in &transaction.steps {
                num_rows += step.execution_state.get_step_height();
            }
        }
        num_rows += 1; // EndBlock
        num_rows
    }

    pub fn get_num_rows_required(block: &Block<F>) -> usize {
        let evm_rows = block.circuits_params.max_evm_rows;
        if evm_rows == 0 {
            Self::get_min_num_rows_required(block)
        } else {
            // It must have at least one unused row.
            block.circuits_params.max_evm_rows + 1
        }
    }

    pub fn get_min_num_rows_required(block: &Block<F>) -> usize {
        let mut num_rows = 0;
        for transaction in &block.txs {
            for step in &transaction.steps {
                num_rows += step.execution_state.get_step_height();
            }
        }

        // It must have one row for EndBlock and at least one unused one
        num_rows + 2
    }
}

impl<F: Field> SubCircuit<F> for EvmCircuit<F> {
    type Config = EvmCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.clone())
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let num_rows_required_for_execution_steps: usize =
            Self::get_num_rows_required_no_padding(block);
        let num_rows_required_for_fixed_table: usize = detect_fixed_table_tags(block)
            .iter()
            .map(|tag| tag.build::<F>().count())
            .sum();
        (
            num_rows_required_for_execution_steps,
            std::cmp::max(
                block.circuits_params.max_evm_rows,
                std::cmp::max(
                    num_rows_required_for_fixed_table,
                    num_rows_required_for_execution_steps,
                ),
            ),
        )
    }

    /// Make the assignments to the EvmCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &crate::util::Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();

        config.load_fixed_table(layouter, self.fixed_table_tags.clone())?;
        config.load_byte_table(layouter)?;
        config.execution.assign_block(layouter, block, challenges)
    }
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
                FixedTableTag::BitwiseAnd | FixedTableTag::BitwiseOr | FixedTableTag::BitwiseXor
            ) || need_bitwise_lookup
        })
        .collect()
}

#[cfg(all(feature = "disabled", test))]
pub(crate) mod cached {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;
    use lazy_static::lazy_static;

    struct Cache {
        cs: ConstraintSystem<Fr>,
        config: (EvmCircuitConfig<Fr>, Challenges),
    }

    lazy_static! {
        /// Cached values of the ConstraintSystem after the EVM Circuit configuration and the EVM
        /// Circuit configuration.  These values are calculated just once.
        static ref CACHE: Cache = {
            let mut meta = ConstraintSystem::<Fr>::default();
            let config = EvmCircuit::<Fr>::configure(&mut meta);
            Cache { cs: meta, config }
        };
    }

    /// Wrapper over the EvmCircuit that behaves the same way and also
    /// implements the halo2 Circuit trait, but reuses the precalculated
    /// results of the configuration which are cached in the public variable
    /// `CACHE`.  This wrapper is useful for testing because it allows running
    /// many unit tests while reusing the configuration step of the circuit.
    pub struct EvmCircuitCached(EvmCircuit<Fr>);

    impl Circuit<Fr> for EvmCircuitCached {
        type Config = (EvmCircuitConfig<Fr>, Challenges);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self(self.0.without_witnesses())
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            *meta = CACHE.cs.clone();
            CACHE.config.clone()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            self.0.synthesize(config, layouter)
        }
    }

    impl EvmCircuitCached {
        pub fn get_test_cicuit_from_block(block: Block<Fr>) -> Self {
            Self(EvmCircuit::<Fr>::get_test_cicuit_from_block(block))
        }
    }
}

// Always exported because of `EXECUTION_STATE_HEIGHT_MAP`

#[cfg(not(feature = "onephase"))]
use crate::util::Challenges;
#[cfg(feature = "onephase")]
use crate::util::MockChallenges as Challenges;

impl<F: Field> Circuit<F> for EvmCircuit<F> {
    type Config = (EvmCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenges_expr = challenges.exprs(meta);
        let rw_table = RwTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let q_copy_table = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_copy_table);
        let keccak_table = KeccakTable::construct(meta);
        let exp_table = ExpTable::construct(meta);
        (
            EvmCircuitConfig::new(
                meta,
                EvmCircuitConfigArgs {
                    challenges: challenges_expr,
                    tx_table,
                    rw_table,
                    bytecode_table,
                    block_table,
                    copy_table,
                    keccak_table,
                    exp_table,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();

        let (config, challenges) = config;
        let challenges = challenges.values(&layouter);

        config.tx_table.load(
            &mut layouter,
            &block.txs,
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.chain_id,
            &challenges,
        )?;
        block.rws.check_rw_counter_sanity();
        config.rw_table.load(
            &mut layouter,
            &block.rws.table_assignments(),
            block.circuits_params.max_rws,
            challenges.evm_word(),
        )?;
        config
            .bytecode_table
            .load(&mut layouter, block.bytecodes.values(), &challenges)?;
        config
            .block_table
            .load(&mut layouter, &block.context, &block.txs, 1, &challenges)?;
        config.copy_table.load(&mut layouter, block, &challenges)?;
        config
            .keccak_table
            .dev_load(&mut layouter, &block.sha3_inputs, &challenges)?;
        config.exp_table.load(&mut layouter, block)?;

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(any(feature = "test", test))]
pub mod test {
    use super::{detect_fixed_table_tags, EvmCircuit};
    use crate::evm_circuit::witness::Block;
    use eth_types::{Field, Word};
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

    impl<F: Field> EvmCircuit<F> {
        pub fn get_test_cicuit_from_block(block: Block<F>) -> Self {
            let fixed_table_tags = detect_fixed_table_tags(&block);
            EvmCircuit::<F>::new_dev(block, fixed_table_tags)
        }
    }
}

#[cfg(test)]
mod evm_circuit_stats {
    use crate::{
        evm_circuit::{
            param::{
                LOOKUP_CONFIG, N_BYTE_LOOKUPS, N_COPY_COLUMNS, N_PHASE1_COLUMNS, N_PHASE2_COLUMNS,
            },
            step::ExecutionState,
            EvmCircuit,
        },
        stats::print_circuit_stats_by_states,
        test_util::CircuitTestBuilder,
        witness::block_convert,
    };
    use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
    use cli_table::{print_stdout, Cell, Style, Table};
    use eth_types::{bytecode, evm_types::OpcodeId, geth_types::GethData, ToWord};
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem},
    };
    use itertools::Itertools;
    #[cfg(feature = "kroma")]
    use mock::test_ctx::helpers::{setup_kroma_required_accounts, system_deposit_tx};
    use mock::{
        test_ctx::{
            helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
            SimpleTestContext, TestContext0_0,
        },
        MOCK_ACCOUNTS,
    };

    #[test]
    pub fn empty_evm_circuit_no_padding() {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext0_0::new(
                None,
                |mut accs| {
                    #[cfg(feature = "kroma")]
                    setup_kroma_required_accounts(accs.as_mut_slice(), 0);
                },
                |mut txs, _| {
                    #[cfg(feature = "kroma")]
                    system_deposit_tx(txs[0]);
                },
                |b, _| b,
            )
            .unwrap(),
        )
        .run();
    }

    #[test]
    pub fn empty_evm_circuit_with_padding() {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext0_0::new(
                None,
                |mut accs| {
                    #[cfg(feature = "kroma")]
                    setup_kroma_required_accounts(accs.as_mut_slice(), 0);
                },
                |mut txs, _| {
                    #[cfg(feature = "kroma")]
                    system_deposit_tx(txs[0]);
                },
                |b, _| b,
            )
            .unwrap(),
        )
        .block_modifier(Box::new(|block| {
            block.circuits_params.max_evm_rows = (1 << 18) - 100
        }))
        .run();
    }

    /// Prints the stats of EVM circuit per execution state.  See
    /// `print_circuit_stats_by_states` for more details.
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release --all-features
    /// get_evm_states_stats -- --nocapture --ignored`
    #[ignore]
    #[test]
    fn get_evm_states_stats() {
        print_circuit_stats_by_states(
            |state| {
                !matches!(
                    state,
                    ExecutionState::ErrorInvalidOpcode | ExecutionState::SELFDESTRUCT
                )
            },
            |opcode| match opcode {
                OpcodeId::RETURNDATACOPY => {
                    bytecode! {
                    PUSH1(0x00) // retLength
                    PUSH1(0x00) // retOffset
                    PUSH1(0x00) // argsLength
                    PUSH1(0x00) // argsOffset
                    PUSH1(0x00) // value
                    PUSH32(MOCK_ACCOUNTS[3].to_word())
                    PUSH32(0x1_0000) // gas
                    CALL
                    PUSH2(0x01) // size
                    PUSH2(0x00) // offset
                    PUSH2(0x00) // destOffset
                    }
                }
                _ => bytecode! {
                    PUSH2(0x40)
                    PUSH2(0x50)
                },
            },
            |_, state, _| state.get_step_height_option().unwrap(),
        );
    }

    /// This function prints to stdout a table with the top X ExecutionState
    /// cell consumers of each EVM Cell type.
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release get_exec_steps_occupancy
    /// --features test -- --nocapture --ignored`
    #[ignore]
    #[test]
    fn get_exec_steps_occupancy() {
        let mut meta = ConstraintSystem::<Fr>::default();
        let circuit = EvmCircuit::configure(&mut meta);

        let report = circuit.0.execution.instrument().clone().analyze();
        macro_rules! gen_report {
            ($report:expr, $($id:ident, $cols:expr), +) => {
                $(
                let row_report = report
                    .iter()
                    .sorted_by(|a, b| a.$id.utilization.partial_cmp(&b.$id.utilization).unwrap())
                    .rev()
                    .take(10)
                    .map(|exec| {
                        vec![
                            format!("{:?}", exec.state),
                            format!("{:?}", exec.$id.available_cells),
                            format!("{:?}", exec.$id.unused_cells),
                            format!("{:?}", exec.$id.used_cells),
                            format!("{:?}", exec.$id.top_height),
                            format!("{:?}", exec.$id.used_columns),
                            format!("{:?}", exec.$id.utilization),
                        ]
                    })
                    .collect::<Vec<Vec<String>>>();

                let table = row_report.table().title(vec![
                    format!("{:?}", stringify!($id)).cell().bold(true),
                    format!("total_available_cells").cell().bold(true),
                    format!("unused_cells").cell().bold(true),
                    format!("cells").cell().bold(true),
                    format!("top_height").cell().bold(true),
                    format!("used columns (Max: {:?})", $cols).cell().bold(true),
                    format!("Utilization").cell().bold(true),
                ]);
                print_stdout(table).unwrap();
                )*
            };
        }

        gen_report!(
            report,
            storage_1,
            N_PHASE1_COLUMNS,
            storage_2,
            N_PHASE2_COLUMNS,
            storage_perm,
            N_COPY_COLUMNS,
            byte_lookup,
            N_BYTE_LOOKUPS,
            fixed_table,
            LOOKUP_CONFIG[0].1,
            tx_table,
            LOOKUP_CONFIG[1].1,
            rw_table,
            LOOKUP_CONFIG[2].1,
            bytecode_table,
            LOOKUP_CONFIG[3].1,
            block_table,
            LOOKUP_CONFIG[4].1,
            copy_table,
            LOOKUP_CONFIG[5].1,
            keccak_table,
            LOOKUP_CONFIG[6].1,
            exp_table,
            LOOKUP_CONFIG[7].1
        );
    }
    #[test]
    fn variadic_size_check() {
        let params = CircuitsParams {
            max_evm_rows: 1 << 12,
            ..Default::default()
        };
        // Empty
        let block: GethData = TestContext0_0::new(
            None,
            |mut accs| {
                #[cfg(feature = "kroma")]
                setup_kroma_required_accounts(accs.as_mut_slice(), 0);
            },
            |mut txs, _| {
                #[cfg(feature = "kroma")]
                system_deposit_tx(txs[0]);
            },
            |b, _| b,
        )
        .unwrap()
        .into();
        let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), params)
            .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        let k = block.get_test_degree();

        let circuit = EvmCircuit::<Fr>::get_test_cicuit_from_block(block);
        let prover1 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

        let code = bytecode! {
            STOP
        };
        let block: GethData = SimpleTestContext::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |b, _| b,
        )
        .unwrap()
        .into();
        let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), params)
            .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        let k = block.get_test_degree();
        let circuit = EvmCircuit::<Fr>::get_test_cicuit_from_block(block);
        let prover2 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover1.fixed(), prover2.fixed());
        assert_eq!(prover1.permutation(), prover2.permutation());
    }
}
