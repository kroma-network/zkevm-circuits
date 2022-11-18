//! The Super Circuit is a circuit that contains all the circuits of the
//! zkEVM in order to achieve two things:
//! - Check the correct integration between circuits via the shared lookup
//!   tables, to verify that the table layouts match.
//! - Allow having a single circuit setup for which a proof can be generated
//!   that would be verified under a single aggregation circuit for the first
//!   milestone.
//!
//! The current implementation contains the following circuits:
//!
//! - [x] EVM Circuit
//! - [ ] State Circuit
//! - [x] Tx Circuit
//! - [x] Bytecode Circuit
//! - [x] Copy Circuit
//! - [ ] Keccak Circuit
//! - [ ] MPT Circuit
//! - [ ] PublicInputs Circuit
//!
//! And the following shared tables, with the circuits that use them:
//!
//! - [x] Copy Table
//!   - [x] Copy Circuit
//!   - [x] EVM Circuit
//! - [ ] Rw Table
//!   - [ ] State Circuit
//!   - [ ] EVM Circuit
//!   - [ ] Copy Circuit
//! - [x] Tx Table
//!   - [x] Tx Circuit
//!   - [x] EVM Circuit
//!   - [x] Copy Circuit
//!   - [ ] PublicInputs Circuit
//! - [x] Bytecode Table
//!   - [x] Bytecode Circuit
//!   - [x] EVM Circuit
//!   - [x] Copy Circuit
//! - [ ] Block Table
//!   - [ ] EVM Circuit
//!   - [ ] PublicInputs Circuit
//! - [ ] MPT Table
//!   - [ ] MPT Circuit
//!   - [ ] State Circuit
//! - [x] Keccak Table
//!   - [ ] Keccak Circuit
//!   - [ ] EVM Circuit
//!   - [x] Bytecode Circuit
//!   - [x] Tx Circuit
//!   - [ ] MPT Circuit

use crate::state_circuit::StateCircuitConfig;
use crate::tx_circuit::{TxCircuit, TxCircuitConfig};

use crate::bytecode_circuit::bytecode_unroller::{
    unroll, Config as BytecodeConfig, UnrolledBytecode,
};

use crate::evm_circuit::{table::FixedTableTag, EvmCircuit};
use crate::table::{BlockTable, BytecodeTable, CopyTable, MptTable, RwTable, TxTable};
use crate::table::PoseidonHashTable;
use crate::util::power_of_randomness_from_instance;
use crate::witness::Block;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use super::copy_circuit::CopyCircuit;
use crate::{
    keccak_circuit::keccak_bit::{KeccakBitCircuit, KeccakBitConfig},
    tx_circuit::sign_verify::POW_RAND_SIZE,
    witness::block_convert,
};
use bus_mapping::mock::BlockData;
use eth_types::geth_types::{self, GethData};
use halo2_proofs::arithmetic::{CurveAffine, Field as Halo2Field};
use halo2_proofs::halo2curves::{
    bn256::Fr,
    group::{Curve, Group},
    secp256k1::Secp256k1Affine,
};
use rand::RngCore;
use strum::IntoEnumIterator;

/// Configuration of the Super Circuit
#[derive(Clone)]
pub struct SuperCircuitConfig<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    tx_table: TxTable,
    rw_table: RwTable,
    mpt_table: MptTable,
    bytecode_table: BytecodeTable,
    block_table: BlockTable,
    copy_table: CopyTable,
    evm_circuit: EvmCircuit<F>,
    state_circuit: StateCircuitConfig<F>,
    tx_circuit: TxCircuitConfig<F>,
    bytecode_circuit: BytecodeConfig<F>,
    copy_circuit: CopyCircuit<F>,
    keccak_circuit: KeccakBitConfig<F>,
}

/// The Super Circuit contains all the zkEVM circuits
#[derive(Default, Debug)]
pub struct SuperCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    // EVM Circuit
    /// Block witness. Usually derived via
    /// `evm_circuit::witness::block_convert`.
    pub block: Block<F>,
    /// Inputs for the keccak circuit
    pub keccak_inputs: Vec<Vec<u8>>,
    /// Passed down to the evm_circuit. Usually that will be
    /// `FixedTableTag::iter().collect()`.
    pub fixed_table_tags: Vec<FixedTableTag>,
    // Tx Circuit
    /// The transaction circuit that will be used in the `synthesize` step.
    pub tx_circuit: TxCircuit<F, MAX_TXS, MAX_CALLDATA>,
    // Bytecode Circuit
    // bytecodes: Vec<UnrolledBytecode<F>>,
    /// The maximium size for the underlying bytecode circuit.
    pub bytecode_size: usize,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    SuperCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    /// Return the number of rows required to verify a given block
    pub fn get_num_rows_required(block: &Block<F>) -> usize {
        let mut cs = ConstraintSystem::default();
        let config = Self::configure(&mut cs);
        config.evm_circuit.get_num_rows_required(block)
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for SuperCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = SuperCircuitConfig<F, MAX_TXS, MAX_CALLDATA>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let rw_table = RwTable::construct(meta);
        let mpt_table = MptTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let q_copy_table = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_copy_table);

        let keccak_circuit = KeccakBitCircuit::configure(meta);
        let keccak_table = keccak_circuit.keccak_table.clone();

        // TODO: should init from hash circuit
        let hash_table = PoseidonHashTable::construct(meta);

        let power_of_randomness = power_of_randomness_from_instance(meta);
        let evm_circuit = EvmCircuit::configure(
            meta,
            power_of_randomness[..31].to_vec().try_into().unwrap(),
            &tx_table,
            &rw_table,
            &bytecode_table,
            &block_table,
            &copy_table,
            &keccak_table,
        );
        let state_circuit = StateCircuitConfig::configure(
            meta,
            power_of_randomness[..31].to_vec().try_into().unwrap(),
            &rw_table,
            &mpt_table,
        );

        Self::Config {
            tx_table: tx_table.clone(),
            rw_table,
            mpt_table,
            bytecode_table: bytecode_table.clone(),
            block_table,
            copy_table,
            evm_circuit,
            state_circuit,
            copy_circuit: CopyCircuit::configure(
                meta,
                &tx_table,
                &rw_table,
                &bytecode_table,
                copy_table,
                q_copy_table,
                power_of_randomness[0].clone(),
            ),
            tx_circuit: TxCircuitConfig::new(
                meta,
                power_of_randomness.clone(),
                tx_table,
                keccak_table.clone(),
            ),
            bytecode_circuit: BytecodeConfig::configure(
                meta,
                power_of_randomness[0].clone(),
                bytecode_table,
                hash_table,
            ),
            keccak_circuit,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // --- EVM Circuit ---
        config
            .evm_circuit
            .load_fixed_table(&mut layouter, self.fixed_table_tags.clone())?;
        config.evm_circuit.load_byte_table(&mut layouter)?;
        config.rw_table.load(
            &mut layouter,
            &self.block.rws.table_assignments(),
            self.block.state_circuit_pad_to,
            self.block.randomness,
        )?;
        config.state_circuit.load(&mut layouter)?;
        config.block_table.load(
            &mut layouter,
            &self.block.context,
            &self.block.txs,
            self.block.randomness,
        )?;
        config
            .copy_table
            .load(&mut layouter, &self.block, self.block.randomness)?;
        config
            .evm_circuit
            .assign_block(&mut layouter, &self.block)?;
        config.state_circuit.assign(
            &mut layouter,
            &self.block.rws.table_assignments(),
            self.block.state_circuit_pad_to,
            self.block.randomness,
        )?;
        // --- Tx Circuit ---
        self.tx_circuit.assign(&config.tx_circuit, &mut layouter)?;
        // --- Bytecode Circuit ---
        let bytecodes: Vec<UnrolledBytecode<F>> = self
            .block
            .bytecodes
            .iter()
            .map(|(_, b)| unroll(b.bytes.clone(), self.block.randomness))
            .collect();
        config.bytecode_circuit.load(&mut layouter)?;
        config.bytecode_circuit.assign(
            &mut layouter,
            self.bytecode_size,
            &bytecodes,
            self.block.randomness,
        )?;
        // --- Keccak Table ---
        config.keccak_circuit.load(&mut layouter)?;
        config.keccak_circuit.assign_from_witness(
            &mut layouter,
            &self.keccak_inputs,
            self.block.randomness,
        )?;
        // --- Copy Circuit ---
        config
            .copy_circuit
            .assign_block(&mut layouter, &self.block, self.block.randomness)?;
        Ok(())
    }
}

impl<const MAX_TXS: usize, const MAX_CALLDATA: usize> SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA> {
    /// From the witness data, generate a SuperCircuit instance with all of the
    /// sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the circuit and
    /// the Public Inputs needed.
    pub fn build(
        geth_data: GethData,
        rng: &mut (impl RngCore + Clone),
    ) -> Result<(u32, Self, Vec<Vec<Fr>>), bus_mapping::Error> {
        let txs = geth_data
            .eth_block
            .transactions
            .iter()
            .map(geth_types::Transaction::from)
            .collect();

        let mut builder =
            BlockData::new_from_geth_data(geth_data.clone()).new_circuit_input_builder();

        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .expect("could not handle block tx");
        let keccak_inputs = builder.keccak_inputs()?;
        let mut block = block_convert(&builder.block, &builder.code_db);

        block.randomness = Fr::random(rng.clone());
        let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(rng).to_affine();

        let fixed_table_tags: Vec<FixedTableTag> = FixedTableTag::iter().collect();
        let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;

        let num_rows_required_for_steps =
            SuperCircuit::<_, MAX_TXS, MAX_CALLDATA>::get_num_rows_required(&block);

        let k = log2_ceil(
            64 + fixed_table_tags
                .iter()
                .map(|tag| tag.build::<Fr>().count())
                .sum::<usize>(),
        );
        let bytecodes_len = block
            .bytecodes
            .iter()
            .map(|(_, bytecode)| bytecode.bytes.len())
            .sum::<usize>();
        let k = k.max(log2_ceil(64 + bytecodes_len));
        let k = k.max(log2_ceil(64 + num_rows_required_for_steps));
        let k = k + 1;
        log::debug!("super circuit uses k = {}", k);

        let mut instance: Vec<Vec<Fr>> = (1..POW_RAND_SIZE + 1)
            .map(|exp| vec![block.randomness.pow_vartime(&[exp as u64, 0, 0, 0]); (1 << k) - 64])
            .collect();
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        instance.push(vec![]);

        let chain_id = block.context.chain_id();
        let tx_circuit = TxCircuit::new(aux_generator, block.randomness, chain_id.as_u64(), txs);

        let circuit = SuperCircuit::<_, MAX_TXS, MAX_CALLDATA> {
            block,
            fixed_table_tags,
            tx_circuit,
            keccak_inputs,
            // Instead of using 1 << k - NUM_BLINDING_ROWS, we use a much smaller number of enabled
            // rows for the Bytecode Circuit because otherwise it penalizes significantly the
            // MockProver verification time.
            bytecode_size: bytecodes_len + 64,
        };
        Ok((k, circuit, instance))
    }
}

#[cfg(test)]
mod super_circuit_tests {
    use super::*;
    use ethers_signers::{LocalWallet, Signer};
    use halo2_proofs::dev::MockProver;
    use mock::{TestContext, MOCK_CHAIN_ID};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::HashMap;

    use eth_types::{address, bytecode, geth_types::GethData, Word};

    // High memory usage test.  Run in serial with:
    // `cargo test [...] skip_ -- --ignored --test-threads 1`
    // NOTE: This test is not run as part of CI because it requires more memory than
    // is available in github workers and so it gets killed before completion.
    #[ignore]
    #[test]
    fn skip_test_super_circuit() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let bytecode = bytecode! {
            GAS
            STOP
        };

        let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

        let addr_a = wallet_a.address();
        let addr_b = address!("0x000000000000000000000000000000000000BBBB");

        let mut wallets = HashMap::new();
        wallets.insert(wallet_a.address(), wallet_a);

        let mut block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(addr_b)
                    .balance(Word::from(1u64 << 20))
                    .code(bytecode);
                accs[1].address(addr_a).balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(Word::from(1_000_000u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        block.sign(&wallets);

        let (k, circuit, instance) =
            SuperCircuit::<_, 1, 32>::build(block, &mut ChaCha20Rng::seed_from_u64(2)).unwrap();
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        let res = prover.verify();
        if let Err(err) = res {
            eprintln!("Verification failures:");
            eprintln!("{:#?}", err);
            panic!("Failed verification");
        }
    }
}
