
    use std::convert::TryInto;

    use crate::{
        evm_circuit::{
            table::FixedTableTag,
            witness::{Block, BlockContext, Bytecode, RwMap, Transaction},
            EvmCircuit,
        },
        rw_table::RwTable,
        util::Expr, state_circuit::{StateCircuit, StateConfig},
    };
    use eth_types::{Field, Word};
    use halo2_proofs::{
        arithmetic::BaseExt,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        pairing::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
        poly::Rotation,
    };
    use itertools::Itertools;
    use rand::{
        distributions::uniform::{SampleRange, SampleUniform},
        random, thread_rng, Rng,
    };
    use strum::IntoEnumIterator;

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

    pub(crate) fn rand_fp() -> Fp {
        Fp::rand()
    }

    #[derive(Clone)]
    pub struct TestCircuitConfig<F> {
        tx_table: [Column<Advice>; 4],
        rw_table: RwTable,
        bytecode_table: [Column<Advice>; 5],
        block_table: [Column<Advice>; 3],
        evm_circuit: EvmCircuit<F>,
        state_circuit: StateConfig<F>,
    }

    impl<F: Field> TestCircuitConfig<F> {
        fn load_txs(
            &self,
            layouter: &mut impl Layouter<F>,
            txs: &[Transaction],
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "tx table",
                |mut region| {
                    let mut offset = 0;
                    for column in self.tx_table {
                        region.assign_advice(
                            || "tx table all-zero row",
                            column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;

                    for tx in txs.iter() {
                        for row in tx.table_assignments(randomness) {
                            for (column, value) in self.tx_table.iter().zip_eq(row) {
                                region.assign_advice(
                                    || format!("tx table row {}", offset),
                                    *column,
                                    offset,
                                    || Ok(value),
                                )?;
                            }
                            offset += 1;
                        }
                    }
                    Ok(())
                },
            )
        }

        fn load_rws(
            &self,
            layouter: &mut impl Layouter<F>,
            rws: &RwMap,
            randomness: F,
        ) -> Result<(), Error> {
            rws.check_rw_counter_sanity();
            /* 
            layouter.assign_region(
                || "rw table",
                |mut region| {
                    //self.rw_table.assign(&mut region, randomness, rws)?;
                    Ok(())
                },
            )*/
            Ok(())
        }

        fn load_bytecodes(
            &self,
            layouter: &mut impl Layouter<F>,
            bytecodes: &[Bytecode],
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "bytecode table",
                |mut region| {
                    let mut offset = 0;
                    for column in self.bytecode_table {
                        region.assign_advice(
                            || "bytecode table all-zero row",
                            column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;

                    for bytecode in bytecodes.iter() {
                        for row in bytecode.table_assignments(randomness) {
                            for (column, value) in self.bytecode_table.iter().zip_eq(row) {
                                region.assign_advice(
                                    || format!("bytecode table row {}", offset),
                                    *column,
                                    offset,
                                    || Ok(value),
                                )?;
                            }
                            offset += 1;
                        }
                    }
                    Ok(())
                },
            )
        }

        fn load_block(
            &self,
            layouter: &mut impl Layouter<F>,
            block: &BlockContext,
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "block table",
                |mut region| {
                    let mut offset = 0;
                    for column in self.block_table {
                        region.assign_advice(
                            || "block table all-zero row",
                            column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;

                    for row in block.table_assignments(randomness) {
                        for (column, value) in self.block_table.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("block table row {}", offset),
                                *column,
                                offset,
                                || Ok(value),
                            )?;
                        }
                        offset += 1;
                    }

                    Ok(())
                },
            )
        }
    }

    #[derive(Default)]
    pub struct TestCircuit<F> {
        block: Block<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    }

    impl<F> TestCircuit<F> {
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
            let tx_table = [(); 4].map(|_| meta.advice_column());
            //let rw_table = RwTable::construct(meta);
            let bytecode_table = [(); 5].map(|_| meta.advice_column());
            let block_table = [(); 3].map(|_| meta.advice_column());

            let power_of_randomness: [Expression<F>; 31] = (1..32)
            .map(|exp| Expression::Constant(F::from_u128(0x1234).pow(&[exp, 0, 0, 0])))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
            

            let state_circuit = StateCircuit::configure(meta);

            Self::Config {
                tx_table,
                rw_table: state_circuit.rw_table.clone(),
                bytecode_table,
                block_table,
                evm_circuit: EvmCircuit::configure(
                    meta,
                    power_of_randomness,
                    &tx_table,
                    &state_circuit.rw_table,
                    &bytecode_table,
                    &block_table,
                ),
                state_circuit
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
            config.load_txs(&mut layouter, &self.block.txs, self.block.randomness)?;
            //config.load_rws(&mut layouter, &self.block.rws, self.block.randomness)?;
            config.load_bytecodes(&mut layouter, &self.block.bytecodes, self.block.randomness)?;
            config.load_block(&mut layouter, &self.block.context, self.block.randomness)?;
            config
                .evm_circuit
                .assign_block_exact(&mut layouter, &self.block)?;

                
                let check_pass = true;
                let stat_circut = if check_pass {
                    // correct
                    StateCircuit::new(self.block.randomness, self.block.rws.clone())
                } else {
                    // should be wrong
                 StateCircuit::new(self.block.randomness + F::from(1u64), self.block.rws.clone())
                };
            stat_circut.synthesize(config.state_circuit, layouter)?;
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
            let (r1, r2) = config.evm_circuit.get_active_rows(&block);
            let max1: usize = (*r1.iter().max().unwrap()).max(*r2.iter().max().unwrap());
            let max2 = max1.max(4000);
            ((0..max2).collect(), (0..max2).collect())
        }
    }

    pub fn run_test_circuit<F: Field>(
        block: Block<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Vec<VerifyFailure>> {
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
                .iter()
                .map(|bytecode| bytecode.bytes.len())
                .sum::<usize>(),
        ));
        let k = k.max(log2_ceil(64 + num_rows_required_for_steps));
        let k = k.max(12);
        println!("evm circuit uses k = {}", k);

        let (active_gate_rows, active_lookup_rows) = TestCircuit::get_active_rows(&block);
        let circuit = TestCircuit::<F>::new(block, fixed_table_tags);
        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        prover.verify_at_rows(active_gate_rows.into_iter(), active_lookup_rows.into_iter())
    }

    pub fn run_test_circuit_incomplete_fixed_table<F: Field>(
        block: Block<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        run_test_circuit(
            block,
            vec![
                FixedTableTag::Zero,
                FixedTableTag::Range5,
                FixedTableTag::Range16,
                FixedTableTag::Range32,
                FixedTableTag::Range64,
                FixedTableTag::Range256,
                FixedTableTag::Range512,
                FixedTableTag::Range1024,
                FixedTableTag::SignByte,
                FixedTableTag::ResponsibleOpcode,
            ],
        )
    }

    pub fn run_test_circuit_complete_fixed_table<F: Field>(
        block: Block<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        run_test_circuit(block, FixedTableTag::iter().collect())
    }