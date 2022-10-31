use integration_tests::{get_client, fuzzer::convert_to_proto, fuzzer::Fuzzed, provers};
use ethers::{
    core::types::{TransactionRequest, Bytes},
    providers::Middleware,
    signers::Signer,
};
use integration_tests::{
    get_provider, get_wallet
};

use std::fs;
use std::env;
use std::thread::sleep;
use std::time::Duration;
use std::fs::metadata;
use std::collections::{HashMap, HashSet};
use log::{info, debug};
use env_logger::Env;


static GENESIS_ADDRESS: &str = "2adc25665018aa1fe0e6bc666dac8fc2697ff9ba";


// we need info level logging but not always
fn debug_log(msg: &str, debug: bool) {
    if debug {
        info!("{}", msg);
    }
}

async fn run_blocks(fuzzed: &Fuzzed, phase: &str, debug: bool) {
    // connect to geth
    let cli = get_client();
    let prov = get_provider();

    debug_log("- Connect to geth", debug);

    // Wait for geth to be online.
    loop {
        match prov.client_version().await {
            Ok(_version) => {
                break;
            }
            Err(_err) => {
                sleep(Duration::from_millis(500));
            }
        }
    }

    // Get addresses
    let coinbase = cli.get_coinbase().await.unwrap();
    
    // map genesis to coinbase
    let mut addresses = HashMap::new();
    addresses.insert(GENESIS_ADDRESS, coinbase);

    // vector to save addresses produced by fuzzer, we use it to find the
    // correct address
    let mut fuzzed_addresses = Vec::new();
    fuzzed_addresses.push(GENESIS_ADDRESS);

    // map fuzzing addresses to existing addresses
    for (i, builtin_addr) in fuzzed.get_builtin_addrs().iter().enumerate() {
        let wallet = get_wallet(i as u32);
        let address = wallet.address();
        addresses.insert(&builtin_addr, address);
        fuzzed_addresses.push(&builtin_addr);
    }

    let mut blocks_to_prove = HashSet::new();

    let mut blocks_sorted_by_number = fuzzed.get_blocks().to_vec();
    blocks_sorted_by_number.sort_by(|a, b| a.get_number().cmp(&b.get_number()));

    debug_log("- Processing Blocks", debug);
    for block in blocks_sorted_by_number {
        debug_log(&format!("---- Block: {:?}", block.get_number()), debug);
        // stop miner to add all transactions in a single block
        cli.miner_stop().await.expect("cannot stop miner");
        let mut pending_txs = Vec::new();
        let mut block_errors = Vec::new();
        let mut block_succeed = 0;

        debug_log("---- Processing Transactions", debug);
        for tx in block.get_transactions() {
            debug_log(&format!("-------- TX: {:?}", tx), debug);
            let from = addresses.get(tx.get_sender()).unwrap();
            let data;

            let mut tx_geth;

            // if we set gas and gas_price the transaction is not completed
            if tx.get_is_create_tx() {
                data = [tx.get_create_tx_constructor(),
                        tx.get_create_tx_constructor_postfix(),
                        tx.get_create_tx_contract(),
                        tx.get_create_tx_contract_postfix()].concat().to_vec();
                tx_geth = TransactionRequest::new()
                    .from(from.clone())
                    .value(tx.get_value());
            } else {
                let to = addresses
                    .get(fuzzed_addresses
                    .get(tx.get_receiver() as usize % fuzzed_addresses.len())
                    .unwrap()).unwrap();
                data = tx.get_call_tx_data().to_vec();
                tx_geth = TransactionRequest::new()
                    .from(from.clone())
                    .to(to.clone())
                    .value(tx.get_value());
            }

            if data.len() > 0 {
                tx_geth.data = Some(Bytes::from(data));
            }

            //println!("{:?}", tx_geth);

            // Submit the transaction and get any error
            let pending_tx = match prov.send_transaction(tx_geth, None).await {
                Ok(r) => Some(r),
                Err(err) => {
                    block_errors.push(format!("error: cannot send transaction: {:?}", err));
                    None
                }
            };
            if let Some(p) = pending_tx {
                pending_txs.push(p)
            }
        }

        // start miner
        cli.miner_start().await.expect("cannot start miner");
        debug_log("---- Mine transactions", debug);
        for tx in pending_txs {
            match tx.await {
                Ok(_) => {
                    block_succeed = block_succeed + 1;
                    ()
                },
                Err(err) => {
                    block_errors.push(format!("error: cannot confirm tx: {:?}", err));
                    ()
                },
            };
        }
        debug_log(&format!("---- Errors: {:?}", block_errors), debug);
        debug_log(&format!("---- Succeed: {}", block_succeed), debug);

        let block_num = prov.get_block_number().await.expect("cannot get block_num");
        blocks_to_prove.insert(block_num);
    }

    debug_log(&format!("- Blocks to prove: {:?}", blocks_to_prove), debug);

    for block_num in blocks_to_prove {
        debug_log(&format!("---- Block: {:?}", block_num), debug);
        // Test EVM circuit block
        if phase == "" || phase == "evm" {
            info!("-------- Prove EVM circuit");
            provers::prove_evm_circuit(block_num.as_u64()).await;
        }

        // Test State circuit block
        if phase == "" || phase == "state" {
            info!("-------- Prove State circuit");
            provers::prove_state_circuit(block_num.as_u64()).await;
        }
        
        // Test tx circuit
        if phase == "" || phase == "tx" {
            info!("-------- Prove TX circuit");
            provers::prove_tx_circuit(block_num.as_u64()).await;
        }

        // Test Bytecode circuit
        if phase == "" || phase == "bytecode" {
            info!("-------- Prove Bytecode circuit");
            provers::prove_bytecode_circuit(block_num.as_u64()).await;
        }

        // Test Copy circuit
        if phase == "" || phase == "copy" {
            info!("-------- Prove Copy circuit");
            provers::prove_copy_circuit(block_num.as_u64()).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2{
        panic!("usage: cargo run --bin test_fuzz PATH [evm|state|tx|bytecode|copy]");
    }
    let mut phase = "";
    if args.len() == 3 {
        phase = &args[2];
    }
    let filepath = args[1].clone();
    let md = metadata(&filepath);
    let path = match md {
        Ok(path) => path,
        Err(error) => panic!("Path does not exist: {:?}", error),
    };  
    if path.is_dir() {
        info!("Processing directory: {}", filepath);
        let files = fs::read_dir(&filepath).unwrap();
        let mut counter = 0;
        for file in files {
            let childer_filepath = file.unwrap().path();
            info!("Processing: {}", &childer_filepath.to_str().unwrap());
            counter = counter + 1;
            let data = fs::read(&childer_filepath).expect("Unable to read file");
            match convert_to_proto(&data) {
                Some(proto) => {
                    run_blocks(&proto, phase, false).await;
                },
                None => (),
            }
        }
        info!("Total files processed: {}", counter);
    } else if path.is_file() {
        info!("Processing file: {}", filepath);
        let data = fs::read(&filepath).expect("Unable to read file");
        match convert_to_proto(&data) {
            Some(proto) => {
                run_blocks(&proto, phase, false).await;
            },
            None => (),
        }
    }
}
