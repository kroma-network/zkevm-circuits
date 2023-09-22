use eth_types::address;
use ethers::{
    core::{
        types::{TransactionRequest, U256},
        utils::WEI_IN_ETHER,
    },
    middleware::SignerMiddleware,
    prelude::k256::ecdsa::SigningKey,
    providers::{Http, Middleware, Provider},
    signers::Wallet,
};
use integration_tests::{
    log_init,
    scenario_utils::{
        compile_contracts, deploy_contract, distribute_eth, init_wallets, ready_provider,
        transfer_erc20_token, TransferContext, NUM_TXS,
    },
    GenDataOutput,
};
use log::info;
use std::{collections::HashMap, sync::Arc};

#[tokio::main]
async fn main() {
    log_init();

    // prepare context of scenarios
    let contracts = compile_contracts().await;
    let prov: Provider<Http> = ready_provider().await;
    let wallets: Vec<Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>> = init_wallets();

    // map between case name and block_height
    let mut blocks = HashMap::new();

    // ETH Transfer: Transfer funds to our account.
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
    info!("- Done(height: {:?})", receipt.block_number);

    // Deploy smart contracts
    let mut deployments = HashMap::new();

    // Deploy "Greeter" contract
    let contract_name = "Greeter";
    let target_contract = contracts.get(contract_name).expect("contract not found");
    let (deploy_height, contract) =
        deploy_contract(&wallets[0], target_contract, U256::from(42)).await;
    blocks.insert(format!("Deploy {contract_name}"), deploy_height);
    deployments.insert(
        contract_name.to_string(),
        (deploy_height, contract.address()),
    );

    // Deploy "OpenZeppelinERC20TestToken" contract
    let contract_name = "OpenZeppelinERC20TestToken";
    let target_contract = contracts.get(contract_name).expect("contract not found");
    let (deploy_height, contract) =
        deploy_contract(&wallets[0], target_contract, wallets[0].address()).await;
    blocks.insert(format!("Deploy {contract_name}"), deploy_height);
    deployments.insert(
        contract_name.to_string(),
        (deploy_height, contract.address()),
    );

    // ETH transfers: Generate a block with multiple transfers
    let case_name = "Multiple transfers 0";
    info!("Doing {:?}", case_name);
    let block_num = distribute_eth(&prov, &wallets[0], &wallets).await;
    blocks.insert(case_name.to_string(), block_num);
    info!("- Done(height: {:?})", block_num);

    // Prepare address and abi of erc20 contract
    let contract_name = "OpenZeppelinERC20TestToken";
    let contract_address = deployments
        .get(contract_name)
        .expect("contract not found")
        .1;
    let contract_abi = &contracts
        .get(contract_name)
        .expect("contract not found")
        .abi;

    // OpenZeppelin ERC20 single failed transfer (wallet2 sends 345.67 Tokens to
    // wallet3, but wallet2 has 0 Tokens)
    let case_name = "ERC20 OpenZeppelin transfer failed";
    info!("Doing {:?}", case_name);
    let exchange_map = [(2, 3, false)]
        .iter()
        .map(|(from_i, to_i, expected_result)| {
            TransferContext::new(
                *from_i,
                *to_i,
                U256::from_dec_str("345670000000000000000").unwrap(),
                *expected_result,
            )
        })
        .collect();

    let block_num = transfer_erc20_token(
        &prov,
        contract_address,
        contract_abi,
        &wallets,
        exchange_map,
        0,
    )
    .await;
    blocks.insert(case_name.to_string(), block_num);
    info!("- Done(height: {:?})", block_num);

    // OpenZeppelin ERC20 single successful transfer (wallet0 sends 123.45 Tokens to
    // wallet4)
    let case_name = "ERC20 OpenZeppelin transfer successful";
    info!("Doing {:?}", case_name);
    let exchange_map = [(0, 4, true)]
        .iter()
        .map(|(from_i, to_i, expected_result)| {
            TransferContext::new(
                *from_i,
                *to_i,
                U256::from_dec_str("123450000000000000000").unwrap(),
                *expected_result,
            )
        })
        .collect();

    let block_num = transfer_erc20_token(
        &prov,
        contract_address,
        contract_abi,
        &wallets,
        exchange_map,
        0,
    )
    .await;
    blocks.insert(case_name.to_string(), block_num);
    info!("- Done(height: {:?})", block_num);

    // OpenZeppelin ERC20 multiple transfers in a single block (some successful,
    // some unsuccessful)
    // - wallet0 -> wallet1 (ok)
    // - wallet2 -> wallet3 (ko)
    // - wallet1 -> wallet0 (ok)
    // - wallet3 -> wallet2 (ko)
    let case_name = "Multiple ERC20 OpenZeppelin transfers";
    info!("Doing {:?}", case_name);
    let base_amount = 0x800000000000000;
    let exchange_map = [(0, 1, true), (2, 3, false), (1, 0, true), (3, 2, false)]
        .iter()
        .enumerate()
        .map(|(i, (from_i, to_i, expected_result))| {
            TransferContext::new(
                *from_i,
                *to_i,
                U256::from(base_amount / (i + 1)),
                *expected_result,
            )
        })
        .collect();

    let block_num = transfer_erc20_token(
        &prov,
        contract_address,
        contract_abi,
        &wallets,
        exchange_map,
        0,
    )
    .await;
    blocks.insert(case_name.to_string(), block_num);
    info!("- Done(height: {:?})", block_num);

    // OpenZeppelin ERC20 multiple type 2 transfers in a single block.
    let case_name = "Multiple ERC20 OpenZeppelin type 2 transfers";
    info!("Doing {:?}", case_name);

    let mut transfer_map = vec![];
    for i in 0..NUM_TXS - 1 {
        let tx_ctx = TransferContext::new(i, i + 1, WEI_IN_ETHER - i, true);
        transfer_map.push(tx_ctx);
    }

    let block_num = transfer_erc20_token(
        &prov,
        contract_address,
        contract_abi,
        &wallets,
        transfer_map,
        2,
    )
    .await;
    blocks.insert(case_name.to_string(), block_num);
    info!("- Done(height: {:?})", block_num);

    let gen_data = GenDataOutput {
        coinbase: address!("0x0000000000000000000000000000000000000000"),
        wallets: wallets.iter().map(|w| w.address()).collect(),
        blocks,
        deployments,
    };
    gen_data.store();
}
