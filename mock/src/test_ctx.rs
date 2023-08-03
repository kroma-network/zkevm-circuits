//! Mock types and functions to generate Test enviroments for ZKEVM tests

use self::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
use crate::{eth, MockAccount, MockBlock, MockTransaction};
use eth_types::{
    geth_types::{Account, BlockConstants, GethData},
    BigEndianHash, Block, Bytecode, Error, GethExecTrace, Transaction, Word, H256,
};
use external_tracer::{trace, TraceConfig};
use itertools::Itertools;

pub use external_tracer::LoggerConfig;
#[cfg(feature = "kroma")]
pub const SYSTEM_DEPOSIT_TX_GAS: u64 = 1000000u64;
#[cfg(not(feature = "kroma"))]
pub const DEPOSIT_TX_GAS: u64 = 0u64;
/// TestContext is a type that contains all the information from a block
/// required to build the circuit inputs.
///
/// It is specifically used to generate Test cases with very precise information
/// details about any specific part of a block. That includes of course, its
/// transactions too and the accounts involved in all of them.
///
/// The intended way to interact with the structure is through the fn `new`
/// which is designed to return a [`GethData`] which then can be used to query
/// any specific part of the logs generated by the transactions executed within
/// this context.
///
/// ## Example
/// ```rust
/// use eth_types::evm_types::{stack::Stack, Gas, OpcodeId};
/// use eth_types::{address, bytecode, geth_types::GethData, word, Bytecode, ToWord, Word};
/// use lazy_static::lazy_static;
/// use mock::test_ctx::{helpers::*, TestContext};
/// // code_a calls code
/// // jump to 0x10 which is outside the code (and also not marked with
///         // JUMPDEST)
/// let code = bytecode! {
///     PUSH1(0x10)
///     JUMP
///     STOP
/// };
/// let code_a = bytecode! {
///     PUSH1(0x0) // retLength
///     PUSH1(0x0) // retOffset
///     PUSH1(0x0) // argsLength
///     PUSH1(0x0) // argsOffset
///     PUSH32(address!("0x000000000000000000000000000000000cafe001").to_word()) // addr
///     PUSH32(0x1_0000) // gas
///     STATICCALL
///     PUSH2(0xaa)
/// };
/// let index = 8; // JUMP
///
/// // Get the execution steps from the external tracer
/// let block: GethData = TestContext::<3, 2>::new(
///     None,
///     |accs| {
///         accs[0]
///             .address(address!("0x0000000000000000000000000000000000000000"))
///             .code(code_a);
///         accs[1].address(address!("0x000000000000000000000000000000000cafe001")).code(code);
///         accs[2]
///             .address(address!("0x000000000000000000000000000000000cafe002"))
///             .balance(Word::from(1u64 << 30));
///     },
///     |mut txs, accs| {
///         txs[0].to(accs[0].address).from(accs[2].address);
///         txs[1]
///             .to(accs[1].address)
///             .from(accs[2].address)
///             .nonce(1);
///     },
///     |block, _tx| block.number(0xcafeu64),
/// )
/// .unwrap()
/// .into();
///
/// // Now we can start generating the traces and items we need to inspect
/// // the behaviour of the generated env.
/// ```
#[derive(Debug)]
pub struct TestContext<const NACC: usize, const NTX: usize> {
    /// chain id
    pub chain_id: u64,
    /// Account list
    pub accounts: [Account; NACC],
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block from geth
    pub eth_block: eth_types::Block<eth_types::Transaction>,
    /// Execution Trace from geth
    pub geth_traces: Vec<eth_types::GethExecTrace>,
}

#[cfg(feature = "kroma")]
#[macro_export]
macro_rules! tx_idx {
    ($n: expr) => {
        $n + 1
    };
}
#[cfg(not(feature = "kroma"))]
#[macro_export]
macro_rules! tx_idx {
    ($n: expr) => {
        $n
    };
}

#[cfg(feature = "kroma")]
macro_rules! nonce {
    ($n: expr) => {
        $n - 1
    };
}
#[cfg(not(feature = "kroma"))]
macro_rules! nonce {
    ($n: expr) => {
        $n
    };
}

#[macro_export]
// Following accounts are added.
// - $NACC - 5: L1Block.sol
// - $NACC - 4: SystemTxDepositor
// - $NACC - 3: ProtocolRewardVault
// - $NACC - 2: ProposerRewardVault
// - $NACC - 1: ValidatorRewardVault
// Following txs are added at the beginning.
// - 0: SystemDepositTx.
macro_rules! declare_test_context {
    ($ty: ident, $NACC: expr, $NTX: expr) => {
        type $ty = TestContext<{ $NACC + 5 }, { $NTX + 1 }>;
    };
}

declare_test_context!(TestContext0_0_, 0, 0);
pub type TestContext0_0 = TestContext0_0_;

declare_test_context!(TestContext1_1_, 1, 1);
pub type TestContext1_1 = TestContext1_1_;

declare_test_context!(TestContext2_1_, 2, 1);
pub type TestContext2_1 = TestContext2_1_;

declare_test_context!(TestContext2_2_, 2, 2);
pub type TestContext2_2 = TestContext2_2_;

declare_test_context!(TestContext2_3_, 2, 3);
pub type TestContext2_3 = TestContext2_3_;

declare_test_context!(TestContext3_1_, 3, 1);
pub type TestContext3_1 = TestContext3_1_;

declare_test_context!(TestContext3_2_, 3, 2);
pub type TestContext3_2 = TestContext3_2_;

declare_test_context!(TestContext4_1_, 4, 1);
pub type TestContext4_1 = TestContext4_1_;

pub type SimpleTestContext = TestContext2_1;

impl<const NACC: usize, const NTX: usize> From<TestContext<NACC, NTX>> for GethData {
    fn from(ctx: TestContext<NACC, NTX>) -> GethData {
        GethData {
            chain_id: ctx.chain_id,
            history_hashes: ctx.history_hashes,
            eth_block: ctx.eth_block,
            geth_traces: ctx.geth_traces.to_vec(),
            accounts: ctx.accounts.into(),
        }
    }
}

impl<const NACC: usize, const NTX: usize> TestContext<NACC, NTX> {
    pub fn new_with_logger_config<FAcc, FTx, Fb>(
        history_hashes: Option<Vec<Word>>,
        acc_fns: FAcc,
        func_tx: FTx,
        func_block: Fb,
        logger_config: LoggerConfig,
    ) -> Result<Self, Error>
    where
        FTx: FnOnce(Vec<&mut MockTransaction>, [MockAccount; NACC]),
        Fb: FnOnce(&mut MockBlock, Vec<MockTransaction>) -> &mut MockBlock,
        FAcc: FnOnce([&mut MockAccount; NACC]),
    {
        let mut accounts: Vec<MockAccount> = vec![MockAccount::default(); NACC];
        // Build Accounts modifiers
        let account_refs = accounts
            .iter_mut()
            .collect_vec()
            .try_into()
            .expect("Mismatched len err");
        acc_fns(account_refs);
        let accounts: [MockAccount; NACC] = accounts
            .iter_mut()
            .map(|acc| acc.build())
            .collect_vec()
            .try_into()
            .expect("Mismatched acc len");

        let mut transactions = vec![MockTransaction::default(); NTX];
        // By default, set the TxIndex and the Nonce values of the multiple transactions
        // of the context correlative so that any Ok test passes by default.
        // If the user decides to override these values, they'll then be set to whatever
        // inputs were provided by the user.
        transactions
            .iter_mut()
            .enumerate()
            .skip(1)
            .for_each(|(idx, tx)| {
                tx.transaction_idx(u64::try_from(idx).expect("Unexpected idx conversion error"));
                tx.nonce(u64::try_from(nonce!(idx)).expect("Unexpected idx conversion error"));
            });
        let tx_refs = transactions.iter_mut().collect();

        // Build Tx modifiers.
        func_tx(tx_refs, accounts.clone());
        let transactions: Vec<MockTransaction> =
            transactions.iter_mut().map(|tx| tx.build()).collect();

        // Build Block modifiers
        let mut block = MockBlock::default();
        let parent_hash = history_hashes
            .as_ref()
            .and_then(|hashes| hashes.last().copied())
            .unwrap_or_default();
        block.parent_hash(H256::from_uint(&parent_hash));
        block.transactions.extend_from_slice(&transactions);
        func_block(&mut block, transactions).build();

        let chain_id = block.chain_id;
        let block = Block::<Transaction>::from(block);
        let accounts: [Account; NACC] = accounts
            .iter()
            .cloned()
            .map(Account::from)
            .collect_vec()
            .try_into()
            .expect("Mismatched acc len");

        let geth_traces = gen_geth_traces(
            chain_id,
            block.clone(),
            accounts.to_vec(),
            history_hashes.clone(),
            logger_config,
        )?;

        Ok(Self {
            chain_id,
            accounts,
            history_hashes: history_hashes.unwrap_or_default(),
            eth_block: block,
            geth_traces,
        })
    }

    /// Create a new TestContext which starts with `NACC` default accounts and
    /// `NTX` default transactions.  Afterwards, we apply the `acc_fns`
    /// function to the accounts, the `func_tx` to the transactions and
    /// the `func_block` to the block, where each of these functions can
    /// mutate their target using the builder pattern. Finally an
    /// execution trace is generated of the resulting input block and state.
    pub fn new<FAcc, FTx, Fb>(
        history_hashes: Option<Vec<Word>>,
        acc_fns: FAcc,
        func_tx: FTx,
        func_block: Fb,
    ) -> Result<Self, Error>
    where
        FTx: FnOnce(Vec<&mut MockTransaction>, [MockAccount; NACC]),
        Fb: FnOnce(&mut MockBlock, Vec<MockTransaction>) -> &mut MockBlock,
        FAcc: FnOnce([&mut MockAccount; NACC]),
    {
        Self::new_with_logger_config(
            history_hashes,
            acc_fns,
            func_tx,
            func_block,
            LoggerConfig::default(),
        )
    }

    /// Returns a simple TestContext setup with a single tx executing the
    /// bytecode passed as parameters. The balances of the 2 accounts and
    /// addresses are the ones used in [`TestContext::
    /// account_0_code_account_1_no_code`]. Extra accounts, txs and/or block
    /// configs are set as [`Default`].
    pub fn simple_ctx_with_bytecode(bytecode: Bytecode) -> Result<SimpleTestContext, Error> {
        TestContext::new(
            None,
            account_0_code_account_1_no_code(bytecode),
            tx_from_1_to_0,
            |block, _txs| block.number(0xcafeu64),
        )
    }
}

/// Generates execution traces for the transactions included in the provided
/// Block
pub fn gen_geth_traces(
    chain_id: u64,
    block: Block<Transaction>,
    accounts: Vec<Account>,
    history_hashes: Option<Vec<Word>>,
    logger_config: LoggerConfig,
) -> Result<Vec<GethExecTrace>, Error> {
    let trace_config = TraceConfig {
        chain_id,
        history_hashes: history_hashes.unwrap_or_default(),
        block_constants: BlockConstants::try_from(&block)?,
        accounts: accounts
            .iter()
            .map(|account| (account.address, account.clone()))
            .collect(),
        transactions: block
            .transactions
            .iter()
            .map(eth_types::geth_types::Transaction::from)
            .collect(),
        logger_config,
    };
    let traces = trace(&trace_config)?;
    Ok(traces)
}

/// Collection of helper functions which contribute to specific rutines on the
/// builder pattern used to construct [`TestContext`]s.
pub mod helpers {
    use super::{eth, Bytecode, MockAccount, MockTransaction};
    use crate::{test_ctx::SYSTEM_DEPOSIT_TX_GAS, MOCK_ACCOUNTS};
    use eth_types::H256;
    #[cfg(feature = "kroma")]
    use eth_types::{
        geth_types::DEPOSIT_TX_TYPE,
        kroma_l1_block::BYTECODE,
        kroma_params::{
            L1_BLOCK, PROPOSER_REWARD_VAULT, PROTOCOL_VAULT, SYSTEM_TX_CALLER,
            VALIDATOR_REWARD_VAULT,
        },
        Bytes, Word,
    };
    use std::str::FromStr;

    /// Generate a simple setup which adds balance to two default accounts from
    /// [`static@MOCK_ACCOUNTS`]:
    /// - 0x000000000000000000000000000000000cafe111
    /// - 0x000000000000000000000000000000000cafe222
    /// And injects the provided bytecode into the first one.
    fn do_account_0_code_account_1_no_code(accs: &mut [&mut MockAccount], code: Bytecode) {
        accs[0]
            .address(MOCK_ACCOUNTS[0])
            .balance(eth(10))
            .code(code);
        accs[1].address(MOCK_ACCOUNTS[1]).balance(eth(10));
    }

    #[cfg(not(feature = "kroma"))]
    pub fn account_0_code_account_1_no_code(code: Bytecode) -> impl FnOnce([&mut MockAccount; 2]) {
        |mut accs| {
            do_account_0_code_account_1_no_code(accs.as_mut_slice(), code);
        }
    }

    #[cfg(feature = "kroma")]
    /// Intercept account_0_code_account_1_no_code and setup accounts for Kroma
    /// unittest.
    pub fn account_0_code_account_1_no_code(code: Bytecode) -> impl FnOnce([&mut MockAccount; 7]) {
        |mut accs| {
            do_account_0_code_account_1_no_code(accs.as_mut_slice(), code);
            setup_kroma_required_accounts(accs.as_mut_slice(), 2);
        }
    }

    #[cfg(feature = "kroma")]
    /// Generate existing accounts in Kroma.
    /// - L1_BLOCK
    /// - SYSTEM_TX_CALLER
    /// - PROTOCOL_VAULT
    /// - PROPOSER_REWARD_VAULT
    /// - VALIDATOR_REWARD_VAULT
    pub fn setup_kroma_required_accounts(accs: &mut [&mut MockAccount], n: usize) {
        accs[n].address(*L1_BLOCK).code(BYTECODE.clone());

        // luke: temporarily add balance to avoid panic on check_update_sdb_account
        accs[n + 1].address(*SYSTEM_TX_CALLER).balance(eth(10));
        accs[n + 2].address(*PROTOCOL_VAULT).balance(eth(10));
        accs[n + 3].address(*PROPOSER_REWARD_VAULT).balance(eth(10));
        accs[n + 4]
            .address(*VALIDATOR_REWARD_VAULT)
            .balance(eth(10));
    }

    /// Generate a single transaction from the second account of the list to the
    /// first one.
    #[cfg(feature = "kroma")]
    pub fn tx_from_1_to_0(mut txs: Vec<&mut MockTransaction>, accs: [MockAccount; 7]) {
        system_deposit_tx(txs[0]);
        do_tx_from_1_to_0(txs[1], accs.as_slice());
    }
    #[cfg(not(feature = "kroma"))]
    pub fn tx_from_1_to_0(mut txs: Vec<&mut MockTransaction>, accs: [MockAccount; 2]) {
        do_tx_from_1_to_0(txs[0], accs.as_slice());
    }
    fn do_tx_from_1_to_0(tx: &mut MockTransaction, accs: &[MockAccount]) {
        tx.from(accs[1].address).to(accs[0].address);
    }

    #[cfg(feature = "kroma")]
    /// Generate a system deposit transaction.
    pub fn system_deposit_tx(tx: &mut MockTransaction) {
        macro_rules! padding {
            ($vec:expr) => {{
                let mut v = $vec;
                let len = v.len();
                for _ in 0..(32 - len) {
                    v.insert(0, 0);
                }
                v
            }};
        }

        let mut calldata = Vec::with_capacity(4 + 32 * 9);

        // setL1BlockValues
        calldata.extend(vec![0xef, 0xc6, 0x74, 0xeb]);
        // l1 blocknumber: 2295
        calldata.extend(padding!(vec![0x08, 0xf7]));
        // l1 timestamp: 1685085294
        calldata.extend(padding!(vec![0x64, 0x70, 0x5c, 0x6e]));
        // l1 basefee: 7
        calldata.extend(padding!(vec![0x07]));
        // l1 hash
        calldata.extend(vec![
            0x36, 0xe0, 0x8a, 0x25, 0xfc, 0x21, 0x49, 0x1f, 0xc3, 0x48, 0xe2, 0xd6, 0x3e, 0x42,
            0xce, 0xda, 0xa3, 0xc6, 0x33, 0x17, 0x80, 0xf2, 0x2b, 0xaa, 0x5e, 0xb4, 0x23, 0x98,
            0x1e, 0xfc, 0x12, 0xa0,
        ]);
        // sequenceNumber: 0
        calldata.extend(vec![0; 32]);
        // batcherHash
        calldata.extend(padding!(vec![
            0x3c, 0x44, 0xcd, 0xdd, 0xb6, 0xa9, 0x00, 0xfa, 0x2b, 0x58, 0x5d, 0xd2, 0x99, 0xe0,
            0x3d, 0x12, 0xfa, 0x42, 0x93, 0xbc
        ]));
        // l1 fee overhead: 2100
        calldata.extend(padding!(vec![0x08, 0x34]));
        // l1 fee scalar: 1000000
        calldata.extend(padding!(vec![0x0f, 0x42, 0x40]));
        // validator reward scalar: 2000
        calldata.extend(padding!(vec![0x07, 0xd0]));

        tx.transaction_type(DEPOSIT_TX_TYPE)
            .from(*SYSTEM_TX_CALLER)
            .to(*L1_BLOCK)
            .gas(Word::from(SYSTEM_DEPOSIT_TX_GAS))
            .gas_price(Word::zero())
            .source_hash(
                H256::from_str(
                    "0x7f9da519dd53cd0705760f80addc46233ba6c3124f4566798ad1ae1fb7189307",
                )
                .unwrap(),
            )
            .mint(Word::from("0x0"))
            .input(Bytes::from(calldata));
    }
}
