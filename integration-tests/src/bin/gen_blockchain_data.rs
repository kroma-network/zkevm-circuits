use eth_types::kroma_params::PROPOSER_FEE_RECIPIENT;
use ethers::{
    abi::{self, Tokenize},
    contract::{builders::ContractCall, Contract, ContractFactory},
    core::{
        types::{
            transaction::eip2718::TypedTransaction, Address, TransactionReceipt,
            TransactionRequest, U256, U64,
        },
        utils::WEI_IN_ETHER,
    },
    middleware::SignerMiddleware,
    providers::{Middleware, PendingTransaction},
    solc::Solc,
};
use integration_tests::{
    get_provider, get_wallet, log_init, CompiledContract, GenDataOutput, CONTRACTS, CONTRACTS_PATH,
};
use log::{error, info};
use std::{collections::HashMap, fs::File, path::Path, sync::Arc, thread::sleep, time::Duration};

async fn deploy_with_result<T, M>(
    prov: Arc<M>,
    compiled: &CompiledContract,
    args: T,
) -> (Contract<M>, TransactionReceipt)
where
    T: Tokenize,
    M: Middleware,
{
    info!("Deploying {}...", compiled.name);
    let factory = ContractFactory::new(compiled.abi.clone(), compiled.bin.clone(), prov);
    factory
        .deploy(args)
        .expect("cannot deploy")
        .confirmations(0usize)
        .send_with_receipt()
        .await
        .expect("cannot confirm deploy")
}

fn erc20_transfer<M>(
    prov: Arc<M>,
    contract_address: Address,
    contract_abi: &abi::Contract,
    to: Address,
    amount: U256,
) -> TypedTransaction
where
    M: Middleware,
{
    let contract = Contract::new(contract_address, contract_abi.clone(), prov);
    let call: ContractCall<M, _> = contract
        .method::<_, bool>("transfer", (to, amount))
        .expect("cannot construct ERC20 transfer call");
    // Set gas to avoid `eth_estimateGas` call
    let call = call.legacy();
    let call = call.gas(100_000);
    call.tx
}

async fn send_confirm_tx<M>(prov: &Arc<M>, tx: TypedTransaction) -> TransactionReceipt
where
    M: Middleware,
{
    prov.send_transaction(tx, None)
        .await
        .expect("cannot send ERC20 transfer call")
        .confirmations(0usize)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::main]
async fn main() {
    log_init();

    // Compile contracts
    info!("Compiling contracts...");
    let mut contracts = HashMap::new();
    for (name, contract_path) in CONTRACTS {
        let path_sol = Path::new(CONTRACTS_PATH).join(contract_path);
        let compiled = Solc::default()
            .compile_source(&path_sol)
            .unwrap_or_else(|_| panic!("solc compile error {:?}", path_sol));
        if !compiled.errors.is_empty() {
            panic!("Errors compiling {:?}:\n{:#?}", &path_sol, compiled.errors)
        }

        let contract = compiled
            .get(path_sol.to_str().expect("path is not str"), name)
            .expect("contract not found");
        let abi = contract.abi.expect("no abi found").clone();
        let bin = contract.bin.expect("no bin found").clone();
        let bin_runtime = contract.bin_runtime.expect("no bin_runtime found").clone();
        let compiled_contract = CompiledContract {
            path: path_sol.to_str().expect("path is not str").to_string(),
            name: name.to_string(),
            abi,
            bin: bin.into_bytes().expect("bin"),
            bin_runtime: bin_runtime.into_bytes().expect("bin_runtime"),
        };

        let mut path_json = path_sol.clone();
        path_json.set_extension("json");
        serde_json::to_writer(
            &File::create(&path_json).expect("cannot create file"),
            &compiled_contract,
        )
        .expect("cannot serialize json into file");

        contracts.insert(name.to_string(), compiled_contract);
    }
    info!("Compiling contracts done...");

    let prov = get_provider();

    // Wait for geth to be online.
    loop {
        match prov.client_version().await {
            Ok(version) => {
                info!("Geth online: {}", version);
                break;
            }
            Err(err) => {
                error!("Geth not available: {:?}", err);
                sleep(Duration::from_millis(500));
            }
        }
    }

    const NUM_TXS: usize = 4; // NUM_TXS must be >= 4 for the rest of the cases to work.
    let wallets: Vec<_> = (0..NUM_TXS + 1)
        .map(|i| Arc::new(SignerMiddleware::new(get_provider(), get_wallet(i as u32))))
        .collect();

    let mut blocks = HashMap::new();

    // ETH Transfer: Transfer funds to our account.
    //

    info!("Transferring funds from wallet0...");
    let tx = TransactionRequest::new()
        .to(wallets[1].address())
        .value(WEI_IN_ETHER) // send 1 ETH
        .from(wallets[0].address());
    let receipt = wallets[0]
        .send_transaction(tx, None)
        .await
        .expect("cannot send tx")
        .await
        .expect("cannot confirm tx")
        .unwrap();
    blocks.insert(
        "Transfer 0".to_string(),
        receipt.block_number.unwrap().as_u64(),
    );

    // Deploy smart contracts
    //

    let mut deployments = HashMap::new();

    // Greeter
    let (contract, receipt) = deploy_with_result(
        wallets[0].clone(),
        contracts.get("Greeter").expect("contract not found"),
        U256::from(42),
    )
    .await;
    blocks.insert(
        "Deploy Greeter".to_string(),
        receipt.block_number.unwrap().as_u64(),
    );
    deployments.insert(
        "Greeter".to_string(),
        (receipt.block_number.unwrap().as_u64(), contract.address()),
    );

    // OpenZeppelinERC20TestToken
    let (contract, receipt) = deploy_with_result(
        wallets[0].clone(),
        contracts
            .get("OpenZeppelinERC20TestToken")
            .expect("contract not found"),
        wallets[0].address(),
    )
    .await;
    blocks.insert(
        "Deploy OpenZeppelinERC20TestToken".to_string(),
        receipt.block_number.unwrap().as_u64(),
    );
    deployments.insert(
        "OpenZeppelinERC20TestToken".to_string(),
        (receipt.block_number.unwrap().as_u64(), contract.address()),
    );

    // ETH transfers: Generate a block with multiple transfers
    //

    info!("Generating block with multiple transfers...");

    // Fund NUM_TXS wallets from wallet0
    let mut block_num: u64;
    loop {
        let mut pending_txs = Vec::new();
        let mut nonce = prov
            .get_transaction_count(wallets[0].address(), None)
            .await
            .expect("cannot get transaction_count");
        let mut i = 0;
        for wallet in &wallets[0..NUM_TXS] {
            info!("send transaction {}", i);
            let tx = TransactionRequest::new()
                .to(wallet.address())
                .nonce(nonce)
                .value(WEI_IN_ETHER * 2u8) // send 2 ETH
                .from(wallets[0].address());
            pending_txs.push(
                wallets[0]
                    .send_transaction(tx, None)
                    .await
                    .expect("cannot send tx"),
            );
            nonce = nonce.checked_add(U256::one()).unwrap();
            i += 1;
        }
        block_num = 0;
        let mut count = 0;
        let mut i = 0;
        for tx in pending_txs {
            info!("confirm transaction {}", i);
            let receipt = tx.await.expect("cannot confirm tx").unwrap();
            info!("block_num: {}", receipt.block_number.unwrap().as_u64());
            if block_num == 0 {
                block_num = receipt.block_number.unwrap().as_u64();
                count += 1;
            } else if block_num == receipt.block_number.unwrap().as_u64() {
                count += 1;
            }
            i += 1;
        }
        if count == NUM_TXS {
            break;
        }
    }
    blocks.insert("Fund wallets".to_string(), block_num);

    // Make NUM_TXS transfers in a "chain"
    loop {
        let mut pending_txs = Vec::new();
        let mut nonce = prov
            .get_transaction_count(wallets[0].address(), None)
            .await
            .expect("cannot get transaction_count");
        for i in 0..NUM_TXS {
            info!("send transaction {}", i);
            let tx = TransactionRequest::new()
                .nonce(nonce)
                .to(wallets[i + 1].address())
                .value(WEI_IN_ETHER / (2 * (i + 1))) // send a fraction of an ETH
                .from(wallets[0].address());
            pending_txs.push(
                wallets[0]
                    .send_transaction(tx, None)
                    .await
                    .expect("cannot send tx"),
            );
            nonce = nonce.checked_add(U256::one()).unwrap();
        }
        block_num = 0;
        let mut count = 0;
        let mut i = 0;
        for tx in pending_txs {
            info!("confirm transaction {}", i);
            let receipt = tx.await.expect("cannot confirm tx").unwrap();
            info!("block_num: {}", receipt.block_number.unwrap().as_u64());
            if block_num == 0 {
                block_num = receipt.block_number.unwrap().as_u64();
                count += 1;
            } else if block_num == receipt.block_number.unwrap().as_u64() {
                count += 1;
            }
            i += 1;
        }
        if count == NUM_TXS {
            break;
        }
    }
    blocks.insert("Multiple transfers 0".to_string(), block_num);

    // ERC20 calls (OpenZeppelin)
    //

    info!("Generating ERC20 calls...");

    let contract_address = deployments
        .get("OpenZeppelinERC20TestToken")
        .expect("contract not found")
        .1;
    let contract_abi = &contracts
        .get("OpenZeppelinERC20TestToken")
        .expect("contract not found")
        .abi;

    // OpenZeppelin ERC20 single failed transfer (wallet2 sends 345.67 Tokens to
    // wallet3, but wallet2 has 0 Tokens)
    info!("Doing OpenZeppelin ERC20 single failed transfer...");
    let amount = U256::from_dec_str("345670000000000000000").unwrap();
    let tx = erc20_transfer(
        wallets[2].clone(),
        contract_address,
        contract_abi,
        wallets[3].address(),
        amount,
    );
    let receipt = send_confirm_tx(&wallets[2], tx).await;
    assert_eq!(receipt.status, Some(U64::from(0u64)));
    blocks.insert(
        "ERC20 OpenZeppelin transfer failed".to_string(),
        receipt.block_number.unwrap().as_u64(),
    );

    // OpenZeppelin ERC20 single successful transfer (wallet0 sends 123.45 Tokens to
    // wallet4)
    info!("Doing OpenZeppelin ERC20 single successful transfer...");
    let amount = U256::from_dec_str("123450000000000000000").unwrap();
    let tx = erc20_transfer(
        wallets[0].clone(),
        contract_address,
        contract_abi,
        wallets[4].address(),
        amount,
    );
    let receipt = send_confirm_tx(&wallets[0], tx).await;
    assert_eq!(receipt.status, Some(U64::from(1u64)));
    blocks.insert(
        "ERC20 OpenZeppelin transfer successful".to_string(),
        receipt.block_number.unwrap().as_u64(),
    );

    // OpenZeppelin ERC20 multiple transfers in a single block (some successful,
    // some unsuccessful)
    // - wallet0 -> wallet1 (ok)
    // - wallet2 -> wallet3 (ko)
    // - wallet1 -> wallet0 (ok)
    // - wallet3 -> wallet2 (ko)
    info!("Doing OpenZeppelin ERC20 multiple transfers...");
    loop {
        let mut tx_hashes = Vec::new();
        for (i, (from_i, to_i)) in [(0, 1), (2, 3), (1, 0), (3, 2)].iter().enumerate() {
            let amount = U256::from(0x800000000000000 / (i + 1));
            let prov_wallet = &wallets[*from_i];
            let tx = erc20_transfer(
                prov_wallet.clone(),
                contract_address,
                contract_abi,
                wallets[*to_i].address(),
                amount,
            );

            let pending_tx = prov_wallet
                .send_transaction(tx, None)
                .await
                .expect("cannot send ERC20 transfer call");
            let tx_hash = *pending_tx; // Deref for PendingTransaction returns TxHash
            tx_hashes.push(tx_hash);
        }
        block_num = 0;
        let mut count = 0;
        for (i, tx_hash) in tx_hashes.iter().enumerate() {
            info!("confirm transaction {}", i);
            let pending_tx = PendingTransaction::new(*tx_hash, wallets[i].inner());
            let receipt = pending_tx.confirmations(0usize).await.unwrap().unwrap();
            let expected_status = u64::from(i % 2 == 0);
            assert_eq!(
                receipt.status,
                Some(U64::from(expected_status)),
                "failed tx hash: {:?}, receipt: {:#?}",
                tx_hash,
                receipt
            );

            info!("block_num: {}", receipt.block_number.unwrap().as_u64());
            if block_num == 0 {
                block_num = receipt.block_number.unwrap().as_u64();
                count += 1;
            } else if block_num == receipt.block_number.unwrap().as_u64() {
                count += 1;
            }
        }
        if count == tx_hashes.len() {
            break;
        }
    }
    blocks.insert(
        "Multiple ERC20 OpenZeppelin transfers".to_string(),
        block_num,
    );

    let gen_data = GenDataOutput {
        coinbase: *PROPOSER_FEE_RECIPIENT,
        wallets: wallets.iter().map(|w| w.address()).collect(),
        blocks,
        deployments,
    };
    gen_data.store();
}
