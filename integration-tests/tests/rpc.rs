#![cfg(feature = "rpc")]

use eth_types::{StorageProof, Word};
use integration_tests::{get_client, CompiledContract, GenDataOutput, CHAIN_ID, CONTRACTS_PATH};
use lazy_static::lazy_static;
use pretty_assertions::assert_eq;
use std::{fs::File, path::Path};

lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

#[tokio::test]
async fn test_get_chain_id() {
    let cli = get_client();
    let chain_id = cli.get_chain_id().await.unwrap();
    assert_eq!(CHAIN_ID, chain_id);
}

#[tokio::test]
async fn test_get_block_by_number_by_hash() {
    let block_num = GEN_DATA.blocks.get("Transfer 0").unwrap();

    let cli = get_client();
    let block_by_num = cli.get_block_by_number((*block_num).into()).await.unwrap();
    let block_by_hash = cli
        .get_block_by_hash(block_by_num.hash.unwrap())
        .await
        .unwrap();
    assert!(block_by_num == block_by_hash);
    // Transaction 2 is a transfer from wallet0 to wallet1
    assert_eq!(block_by_num.transactions.len(), 2);
    assert_eq!(block_by_num.transactions[1].from, GEN_DATA.wallets[0]);
    assert_eq!(block_by_num.transactions[1].to, Some(GEN_DATA.wallets[1]));
}

#[tokio::test]
async fn test_trace_block_by_number_by_hash() {
    let block_num = GEN_DATA.deployments.get("Greeter").unwrap().0;

    let cli = get_client();
    let block = cli.get_block_by_number(block_num.into()).await.unwrap();
    let trace_by_number = cli.trace_block_by_number(block_num.into()).await.unwrap();
    let trace_by_hash = cli.trace_block_by_hash(block.hash.unwrap()).await.unwrap();
    assert_eq!(trace_by_number, trace_by_hash);
    assert!(!trace_by_number[0].struct_logs.is_empty())
}

#[tokio::test]
async fn test_get_contract_code() {
    let contract_name = "Greeter";
    let contract_path_json = "greeter/Greeter.json";

    let (block_num, address) = GEN_DATA.deployments.get(contract_name).unwrap();
    let path_json = Path::new(CONTRACTS_PATH).join(contract_path_json);
    let compiled: CompiledContract =
        serde_json::from_reader(File::open(path_json).expect("cannot read file"))
            .expect("cannot deserialize json from file");

    let cli = get_client();
    let code = cli.get_code(*address, (*block_num).into()).await.unwrap();
    assert_eq!(compiled.bin_runtime.to_vec(), code);
}

#[tokio::test]
async fn test_get_proof() {
    let (block_num, address) = GEN_DATA.deployments.get("Greeter").unwrap();
    // Key 0 corresponds to `Greeter.number`, which is initialized with 0x2a.
    let expected_storage_proof_json = r#"{
         "key": "0x0",
         "value": "0x2a",
         "proof": [
            "0x012098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b6486401010000000000000000000000000000000000000000000000000000000000000000002a00",
            "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
         ]
    }"#;
    let expected_storage_proof: StorageProof =
        serde_json::from_str(expected_storage_proof_json).unwrap();

    let cli = get_client();
    let keys = vec![Word::from(0)];
    let proof = cli
        .get_proof(*address, keys, (*block_num).into())
        .await
        .unwrap();
    assert_eq!(expected_storage_proof, proof.storage_proof[0]);
}
