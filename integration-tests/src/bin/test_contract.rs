use log::{debug, info};
use std::collections::HashMap;
use ethers::{
    abi::{self, Tokenizable},
    contract::{builders::ContractCall, Contract, ContractFactory},
    core::types::{
        transaction::eip2718::TypedTransaction, Address, TransactionRequest,
        U256, 
    },
    core::utils::WEI_IN_ETHER,
    middleware::SignerMiddleware,
    providers::Middleware,
    signers::{Signer, Wallet},
    solc::Solc,
    providers::{Http, Provider},
    types::H160,
};
use bus_mapping::rpc::GethClient;
use integration_tests::{
    get_client, get_provider, get_wallet, CompiledContract, 
    CONTRACTS_PATH, provers, mutations
};
use std::sync::Arc;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
use env_logger::Env;
use std::env;
use lazy_static::lazy_static;

lazy_static! {
    static ref TESTS: HashMap<&'static str, (&'static str, &'static str)> = {
        let m = HashMap::from([
            ("Mul", ("mul/Mul.sol", "mul")),
        ]);
        m
    };
}

const MUTATE: bool = true;

fn compile_contract(contract_name: &str, contract_path: &str) -> CompiledContract {
    let path_sol = Path::new(CONTRACTS_PATH).join(contract_path);
    let compiled = Solc::default()
        .compile_source(&path_sol)
        .expect("solc compile error");
    if !compiled.errors.is_empty() {
        panic!("Errors compiling {:?}:\n{:#?}", &path_sol, compiled.errors)
    }

    let contract = compiled
        .get(path_sol.to_str().expect("path is not str"), contract_name)
        .expect("contract not found");
    let abi = contract.abi.expect("no abi found").clone();
    let bin = contract.bin.expect("no bin found").clone();
    let bin_runtime = contract.bin_runtime.expect("no bin_runtime found").clone();
    let compiled = CompiledContract {
        path: path_sol.to_str().expect("path is not str").to_string(),
        name: contract_name.to_string(),
        abi,
        bin: bin.into_bytes().expect("bin"),
        bin_runtime: bin_runtime.into_bytes().expect("bin_runtime"),
    };
    return compiled;
}

async fn connect_to_geth() -> (GethClient<Http>, Provider<Http>) {
    let cli = get_client();
    let prov = get_provider();
    loop {
        match prov.client_version().await {
            Ok(version) => {
                info!("Geth online: {}", version);
                break;
            }
            Err(err) => {
                debug!("Geth not available: {:?}", err);
                sleep(Duration::from_millis(500));
            }
        }
    }
    return (cli, prov);
}

type WalletProvider = Arc<SignerMiddleware<ethers::providers::Provider<Http>, Wallet<ethers::core::k256::ecdsa::SigningKey>>>;
async fn get_wallet_with_funds(cli: GethClient<Http>, prov: Provider<Http>, index: u32) -> WalletProvider {
    let coinbase = cli.get_coinbase().await.unwrap();
    let wallet0 = get_wallet(index);
    let tx = TransactionRequest::new()
        .to(wallet0.address())
        .value(WEI_IN_ETHER) // send 1 ETH
        .from(coinbase);
    prov.send_transaction(tx, None)
        .await
        .expect("cannot send tx")
        .await
        .expect("cannot confirm tx");
    let prov_wallet0 = Arc::new(SignerMiddleware::new(get_provider(), wallet0));
    return prov_wallet0;
}

async fn deploy_contract(wallet_provider: WalletProvider, compiled: &CompiledContract) -> H160 {
    let factory = ContractFactory::new(compiled.abi.clone(), compiled.bin.clone(), wallet_provider.clone());
    let contract_address = factory
        .deploy(())
        .expect("cannot deploy")
        .confirmations(0usize)
        .send()
        .await
        .expect("cannot confirm deploy").address();
    return contract_address;
}

fn call_contract<M, T: Tokenizable, R: Tokenizable>(
    prov: Arc<M>,
    contract_address: Address,
    contract_abi: &abi::Contract,
    method: &str,
    args: T
) -> TypedTransaction
where
    M: Middleware,
{
    let contract = Contract::new(contract_address, contract_abi.clone(), prov);
    let call: ContractCall<M, _> = contract
        .method::<_, R>(method, args)
        .expect("cannot perform contract call");
    // Set gas to avoid `eth_estimateGas` call
    let call = call.legacy();
    let call = call.gas(100_000);
    call.tx
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);
    if args.len() < 3 {
        panic!("usage: cargo run --release --bin test_contract CONTRACT $pwd");
    }
    let name = &args[1].as_str();
    let entry_path = &args[1].as_str();

    if !TESTS.contains_key(name) {
        panic!("Key {} does not exists in {:?}", name, TESTS.keys());
    }

    let (contract_path, func_name) = TESTS[name];
    let mut contract_path = contract_path.to_owned();
    contract_path.push_str(entry_path);

    info!("Compiling contracts...");
    let compiled = compile_contract(name, contract_path.as_str());

    info!("Conecting to geth...");
    let (cli, prov) = connect_to_geth().await;

    info!("Transferring funds from coinbase...");
    let prov_wallet0 = get_wallet_with_funds(cli, prov.clone(), 0).await;
    let block_num = prov.get_block_number().await.expect("cannot get block_num");
    info!("Transferred {}", block_num); 

    info!("Deploying {}...", compiled.name);
    let contract_address = deploy_contract(prov_wallet0.clone(), &compiled).await;
    let block_num = prov.get_block_number().await.expect("cannot get block_num");
    info!("Deployed {}", block_num); 

    info!("Calling {}...", compiled.name);
    let tx = call_contract::<_, _, U256>(
        prov_wallet0.clone(),
        contract_address,
        &compiled.abi,
        func_name,
        U256::from(5)
    );
    let pending_tx = prov_wallet0
        .send_transaction(tx, None)
        .await
        .expect("Cannot send contract call tx");
    pending_tx.confirmations(0usize).await.unwrap().unwrap();
    let block_num = prov.get_block_number().await.expect("cannot get block_num");
    info!("Called {}", block_num); 

    let block_num = prov.get_block_number().await.expect("cannot get block_num");
    //info!("Proving {}...", block_num);
    //provers::prove_all_circuits(block_num.as_u64()).await;
    //info!("Proved {}", block_num);

    if MUTATE {
        let (builder, _) = provers::get_builder(block_num.as_u64()).await;
        info!("Mutate {}...", block_num);
        let builder = mutations::mutate(builder);  
        info!("Mutated");
        //info!("Prove Mutated {}...", block_num);
        //provers::prove_evm_circuit_direct(builder).await;
        //info!("Proved Mutated");
    }
}

