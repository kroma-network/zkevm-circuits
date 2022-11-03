//! ZKEVM provers
use bus_mapping::circuit_input_builder::{BuilderClient, CircuitInputBuilder};
use bus_mapping::operation::OperationContainer;
use halo2_proofs::halo2curves::FieldExt;
use zkevm_circuits::bytecode_circuit::dev::test_bytecode_circuit;
use zkevm_circuits::copy_circuit::dev::test_copy_circuit;
use zkevm_circuits::evm_circuit::witness::RwMap;
use zkevm_circuits::evm_circuit::{test::run_test_circuit, witness::block_convert};
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::tx_circuit::{
    sign_verify::SignVerifyChip, Secp256k1Affine, TxCircuit
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::marker::PhantomData;
use eth_types::geth_types;
use halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        group::{Curve, Group},
    },
};

use crate::get_client;
use crate::CHAIN_ID;

///Get builder
pub async fn get_builder(block_number: u64) -> (CircuitInputBuilder, eth_types::Block<eth_types::Transaction>) {
    let block_cli = get_client();
    let builder_cli = BuilderClient::new(block_cli).await.unwrap();
    let (builder, eth_block) = builder_cli.gen_inputs(block_number).await.unwrap();
    return (builder, eth_block);
}

/// Prove and verify evm circuit given a builder
pub async fn prove_evm_circuit_direct(builder: CircuitInputBuilder) {
    let block = block_convert(&builder.block, &builder.code_db);
    run_test_circuit(block).expect("evm_circuit verification failed");
}

/// Prove and verify evm circuit
pub async fn prove_evm_circuit(block_number: u64) {
    let (builder, _) = get_builder(block_number).await;
    prove_evm_circuit_direct(builder).await;
}

/// Prove and verify state circuit given a builder
pub async fn prove_state_circuit_direct(builder: CircuitInputBuilder) {
    // Generate state proof
    let stack_ops = builder.block.container.sorted_stack();
    let memory_ops = builder.block.container.sorted_memory();
    let storage_ops = builder.block.container.sorted_storage();

    const STATE_DEGREE: usize = 17;

    let rw_map = RwMap::from(&OperationContainer {
        memory: memory_ops,
        stack: stack_ops,
        storage: storage_ops,
        ..Default::default()
    });

    let randomness = Fr::from(0xcafeu64);
    let circuit = StateCircuit::<Fr>::new(randomness, rw_map, 1 << 16);
    let power_of_randomness = circuit.instance();

    let prover = MockProver::<Fr>::run(STATE_DEGREE as u32, &circuit, power_of_randomness).unwrap();
    prover.verify().expect("state_circuit verification failed");
}

/// Prove and verify state circuit
pub async fn prove_state_circuit(block_number: u64) {
    let (builder, _) = get_builder(block_number).await;
    prove_state_circuit_direct(builder).await;
}

/// Prove and verify tx circuit given eth_block
pub async fn prove_tx_circuit_direct(eth_block: eth_types::Block<eth_types::Transaction>) {
    const TX_DEGREE: u32 = 20;
    let txs: Vec<_> = eth_block
        .transactions
        .iter()
        .map(geth_types::Transaction::from)
        .collect();

    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();

    let circuit = TxCircuit::<Fr, 4, { 4 * (4 + 32 + 32) }> {
        sign_verify: SignVerifyChip {
            aux_generator,
            window_size: 2,
            _marker: PhantomData,
        },
        randomness: Fr::from_u128(0x10000),
        txs,
        chain_id: CHAIN_ID,
    };

    let prover = MockProver::run(TX_DEGREE, &circuit, vec![vec![]]).unwrap();

    prover.verify().expect("tx_circuit verification failed");
}

/// Prove and verify tx circuit
pub async fn prove_tx_circuit(block_number: u64) {
    let (_, eth_block) = get_builder(block_number).await;
    prove_tx_circuit_direct(eth_block).await;
}

/// Prove and verify bytecode circuit given a builder
pub async fn prove_bytecode_circuit_direct(builder: CircuitInputBuilder) {
    const BYTECODE_DEGREE: u32 = 16;
    let bytecodes: Vec<Vec<u8>> = builder.code_db.0.values().cloned().collect();
    test_bytecode_circuit::<Fr>(BYTECODE_DEGREE, bytecodes, Fr::from_u128(0x1000));
}

/// Prove and verify bytecode circuit
pub async fn prove_bytecode_circuit(block_number: u64) {
    let (builder, _) = get_builder(block_number).await;
    prove_bytecode_circuit_direct(builder).await;
}

/// Prove and verify copy circuit given a builder
pub async fn prove_copy_circuit_direct(builder: CircuitInputBuilder) {
    const COPY_DEGREE: u32 = 16;
    let block = block_convert(&builder.block, &builder.code_db);

    assert!(test_copy_circuit(COPY_DEGREE, block).is_ok());
}

/// Prove and verify copy circuit
pub async fn prove_copy_circuit(block_number: u64) {
    let (builder, _) = get_builder(block_number).await;
    prove_copy_circuit_direct(builder).await;
}

/// Prove and verify all circuits
pub async fn prove_all_circuits(block_number: u64) {
    prove_evm_circuit(block_number).await;
    prove_state_circuit(block_number).await;
    prove_tx_circuit(block_number).await;
    prove_bytecode_circuit(block_number).await;
    prove_copy_circuit(block_number).await;
}
