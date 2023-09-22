use eth_types::{Address, U256};
use ethers::{
    abi::{self, Tokenize},
    contract::Contract,
    prelude::{k256::ecdsa::SigningKey, ContractFactory, SignerMiddleware},
    providers::{Http, Middleware, PendingTransaction, Provider},
    signers::Wallet,
    solc::Solc,
    types::TransactionRequest,
    utils::WEI_IN_ETHER,
};
use log::{error, info};
use std::{collections::HashMap, fs::File, path::Path, sync::Arc, thread::sleep, time::Duration};

use crate::{get_provider, get_wallet, CompiledContract, CONTRACTS, CONTRACTS_PATH};

/// Number of transactions in each scenario
/// it must be >= 4 for the rest of the cases to work.
pub const NUM_TXS: usize = 99;
/// Wallet Type
pub type WalletType = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

/// Wait for geth to be online.
pub async fn ready_provider() -> Provider<Http> {
    let prov: Provider<Http> = get_provider();
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
    prov
}

/// Init wallets to be used in each scenario
pub fn init_wallets() -> Vec<WalletType> {
    (0..NUM_TXS + 1)
        .map(|i| Arc::new(SignerMiddleware::new(get_provider(), get_wallet(i as u32))))
        .collect()
}

/// Return map of compiled contracts
pub async fn compile_contracts() -> HashMap<String, CompiledContract> {
    // Compile contracts
    let mut contracts = HashMap::new();
    for (name, contract_path) in CONTRACTS {
        let path_sol = Path::new(CONTRACTS_PATH).join(contract_path);
        let compiled = Solc::default()
            .compile_source(&path_sol)
            .unwrap_or_else(|_| panic!("solc compile error {path_sol:?}"));
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

    contracts
}

/// Deploy contract
pub async fn deploy_contract<M, T>(
    wallet: &Arc<M>,
    compiled: &CompiledContract,
    args: T,
) -> (u64, Contract<M>)
where
    M: Middleware,
    T: Tokenize,
{
    let factory = ContractFactory::new(compiled.abi.clone(), compiled.bin.clone(), wallet.clone());
    let (contract, receipt) = factory
        .deploy(args)
        .unwrap_or_else(|_| panic!("cannot construct contract creation tx: {:?}", compiled.name))
        .confirmations(0usize)
        .send_with_receipt()
        .await
        .unwrap_or_else(|_| panic!("cannot send creation tx: {:?}", compiled.name));

    (receipt.block_number.unwrap().as_u64(), contract)
}

/// A `sender` account sends ETH to multiple accounts
pub async fn distribute_eth(
    prov: &Provider<Http>,
    sender: &WalletType,
    wallets: &[WalletType],
) -> u64 {
    // Fund NUM_TXS wallets from wallet0
    let mut pending_txs = Vec::new();
    let mut nonce = prov
        .get_transaction_count(sender.address(), None)
        .await
        .expect("cannot get transaction_count");

    for wallet in wallets[0..NUM_TXS].iter() {
        let tx = TransactionRequest::new()
            .to(wallet.address())
            .nonce(nonce)
            .value(WEI_IN_ETHER * 2u8) // send 2 ETH
            .from(sender.address());
        pending_txs.push(
            wallets[0]
                .send_transaction(tx, None)
                .await
                .expect("cannot send tx"),
        );
        nonce = nonce.checked_add(U256::one()).unwrap();
    }

    wait_pending_txs(pending_txs).await
}

/// Wait pending transactions
pub async fn wait_pending_txs(pending_txs: Vec<PendingTransaction<'_, Http>>) -> u64 {
    let mut block_num = 0;
    for tx in pending_txs.into_iter() {
        let receipt = tx.await.expect("cannot confirm tx").unwrap();
        log::info!(" - txHash: {}", receipt.transaction_hash);
        if block_num == 0 {
            block_num = receipt.block_number.unwrap().as_u64();
        } else if block_num != receipt.block_number.unwrap().as_u64() {
            panic!("The txs are not in a block")
        }
    }
    block_num
}

/// TransferContext
pub struct TransferContext {
    /// Index of `from` wallet
    pub from: usize,
    /// Index of `to` wallet
    pub to: usize,
    /// Amount to transfer
    pub amount: U256,
    /// Expected result
    pub expected: bool,
}

impl TransferContext {
    /// init an instance
    pub fn new(from: usize, to: usize, amount: U256, expected: bool) -> Self {
        Self {
            from,
            to,
            amount,
            expected,
        }
    }
}

/// Build and return erc20 transfer transaction
/// TODO(dongchangYoo): this function does not support sending multiple txs from an account.
pub async fn transfer_erc20_token(
    prov: &Provider<Http>,
    contract_address: Address,
    contract_abi: &abi::Contract,
    wallets: &[WalletType],
    exchange_map: Vec<TransferContext>,
    tx_type: usize,
) -> u64 {
    let contract = Contract::new(contract_address, contract_abi.clone(), prov.clone());

    let mut pending_txs = Vec::new();
    for trans_ctx in exchange_map.iter() {
        let call = contract
            .method::<_, bool>(
                "transfer",
                (wallets[trans_ctx.to].address(), trans_ctx.amount),
            )
            .expect("cannot construct ERC20 transfer call");

        // Set gas to avoid `eth_estimateGas` call
        let call = call.gas(100_000);

        // Convert tx to legacy tx if tx_type equals to 0
        // TODO(dongchangYoo): use constant for tx_type after implementing various tx types
        let tx = if tx_type == 0 {
            let call = call.legacy();
            call.tx
        } else {
            call.tx
        };

        pending_txs.push(
            wallets[trans_ctx.from]
                .send_transaction(tx, None)
                .await
                .expect("cannot send tx"),
        )
    }

    wait_pending_txs(pending_txs).await
}
