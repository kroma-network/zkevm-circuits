use crate::{evm_circuit::witness::Block, state_circuit::StateCircuit};
use bus_mapping::mock::BlockData;
use eth_types::geth_types::GethData;
use halo2_proofs::dev::{MockProver, VerifyFailure};
use halo2_proofs::pairing::bn256::Fr;
use mock::TestContext;

#[cfg(test)]
#[ctor::ctor]
fn init_env_logger() {
    // Enable RUST_LOG during tests
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
}

#[derive(Debug, Clone)]
pub struct BytecodeTestConfig {
    pub enable_evm_circuit_test: bool,
    pub enable_state_circuit_test: bool,
    pub gas_limit: u64,
}

impl Default for BytecodeTestConfig {
    fn default() -> Self {
        Self {
            enable_evm_circuit_test: true,
            enable_state_circuit_test: true,
            gas_limit: 1_000_000u64,
        }
    }
}

pub fn run_test_circuits<const NACC: usize, const NTX: usize>(
    test_ctx: TestContext<NACC, NTX>,
    config: Option<BytecodeTestConfig>,
) -> Result<(), Vec<VerifyFailure>> {
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();

    // build a witness block from trace result
    let block = crate::evm_circuit::witness::block_convert(&builder.block, &builder.code_db);

    // finish required tests according to config using this witness block
    test_circuits_using_witness_block(block, config.unwrap_or_default())
}

pub fn test_circuits_using_witness_block(
    block: Block<Fr>,
    config: BytecodeTestConfig,
) -> Result<(), Vec<VerifyFailure>> {
    // run evm circuit test
    if config.enable_evm_circuit_test {
        crate::evm_circuit::test::run_test_circuit(block.clone())?;
    }

    // run state circuit test
    // TODO: use randomness as one of the circuit public input, since randomness in
    // state circuit and evm circuit must be same
    if config.enable_state_circuit_test {
        const N_ROWS: usize = 1 << 16;
        let state_circuit = StateCircuit::<Fr>::new(block.randomness, block.rws, N_ROWS);
        let power_of_randomness = state_circuit.instance();
        let prover = MockProver::<Fr>::run(18, &state_circuit, power_of_randomness).unwrap();
        prover.verify_at_rows(
            N_ROWS - state_circuit.rows.len()..N_ROWS,
            N_ROWS - state_circuit.rows.len()..N_ROWS,
        )?
    }

    Ok(())
}
