use bus_mapping::{
    circuit_input_builder::{BuilderClient, ExecState},
    evm::OpcodeId,
};
use halo2_proofs::{dev::MockProver, pairing::bn256::Fr};
use integration_tests::{get_client, log_init, FAST, TX_ID};
use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::{
    table::FixedTableTag, test::TestCircuit, witness::block_convert,
};

#[tokio::main]
async fn main() {
    log_init();
    log::info!("test evm circuit, tx: {}", *TX_ID);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli.gen_inputs_tx(&*TX_ID).await.unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db);
    let need_bitwise_lookup = builder.block.txs.iter().any(|tx| {
        tx.steps().iter().any(|step| {
            matches!(
                step.exec_state,
                ExecState::Op(OpcodeId::ADD)
                    | ExecState::Op(OpcodeId::OR)
                    | ExecState::Op(OpcodeId::XOR)
            )
        })
    });

    let fixed_table_tags = FixedTableTag::iter()
        .filter(|t| {
            need_bitwise_lookup
                || !matches!(
                    t,
                    FixedTableTag::BitwiseAnd
                        | FixedTableTag::BitwiseOr
                        | FixedTableTag::BitwiseXor
                )
        })
        .collect();
    let (active_gate_rows, active_lookup_rows) = TestCircuit::get_active_rows(&block);

    let circuit = TestCircuit::<Fr>::new(block, fixed_table_tags);
    let k = circuit.estimate_k();
    let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
    if *FAST {
        prover
            .verify_at_rows_par(active_gate_rows.into_iter(), active_lookup_rows.into_iter())
            .unwrap();
    } else {
        prover.verify_par().unwrap();
    }
    log::info!("prove done");
}
