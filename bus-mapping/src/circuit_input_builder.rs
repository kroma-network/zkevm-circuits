//! This module contains the CircuitInputBuilder, which is an object that takes
//! types from geth / web3 and outputs the circuit inputs.

mod access;
mod block;
mod call;
mod execution;
mod input_state_ref;
#[cfg(test)]
mod tracer_tests;
mod transaction;

use self::access::gen_state_access_trace;
pub use self::block::BlockHead;
use crate::error::Error;
use crate::evm::opcodes::{gen_associated_ops, gen_begin_tx_ops, gen_end_tx_ops};
#[cfg(feature = "kanvas")]
use crate::evm::opcodes::{gen_end_deposit_tx_ops, gen_fee_hook_ops};
use crate::operation::{CallContextField, RW};
use crate::rpc::GethClient;
use crate::state_db::{self, CodeDB, StateDB};
pub use access::{Access, AccessSet, AccessValue, CodeSource};
pub use block::{Block, BlockContext};
pub use call::{Call, CallContext, CallKind};
use core::fmt::Debug;
use eth_types::evm_types::GasCost;
use eth_types::geth_types;
#[cfg(feature = "kanvas")]
use eth_types::geth_types::DEPOSIT_TX_TYPE;
#[cfg(feature = "kanvas")]
use eth_types::kanvas_params::{BASE_FEE_RECIPIENT, L1_FEE_RECIPIENT};
use eth_types::sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData};
use eth_types::{self, Address, GethExecStep, GethExecTrace, ToWord, Word, H256, U256};
use ethers_providers::JsonRpcClient;
pub use execution::{CopyDataType, CopyEvent, CopyStep, ExecState, ExecStep, NumberOrHash};
use hex::decode_to_slice;
pub use input_state_ref::CircuitInputStateRef;
use itertools::Itertools;
use std::collections::{BTreeMap, HashMap};
pub use transaction::{Transaction, TransactionContext};

/// Builder to generate a complete circuit input from data gathered from a geth
/// instance. This structure is the centre of the crate and is intended to be
/// the only entry point to it. The `CircuitInputBuilder` works in several
/// steps:
///
/// 1. Take a [`eth_types::Block`] to build the circuit input associated with
/// the block. 2. For each [`eth_types::Transaction`] in the block, take the
/// [`eth_types::GethExecTrace`] to build the circuit input associated with
/// each transaction, and the bus-mapping operations associated with each
/// [`eth_types::GethExecStep`] in the [`eth_types::GethExecTrace`].
///
/// The generated bus-mapping operations are:
/// [`StackOp`](crate::operation::StackOp)s,
/// [`MemoryOp`](crate::operation::MemoryOp)s and
/// [`StorageOp`](crate::operation::StorageOp), which correspond to each
/// [`OpcodeId`](crate::evm::OpcodeId)s used in each `ExecTrace` step so that
/// the State Proof witnesses are already generated on a structured manner and
/// ready to be added into the State circuit.
#[derive(Debug)]
pub struct CircuitInputBuilder {
    /// StateDB key-value DB
    pub sdb: StateDB,
    /// Map of account codes by code hash
    pub code_db: CodeDB,
    /// Block
    pub block: Block,
    /// Block Context
    pub block_ctx: BlockContext,
}

impl<'a> CircuitInputBuilder {
    /// Create a new CircuitInputBuilder from the given `eth_block` and
    /// `constants`.
    pub fn new(sdb: StateDB, code_db: CodeDB, headers: &[BlockHead]) -> Self {
        Self {
            sdb,
            code_db,
            // lispczz@scroll:
            // the `block` here is in fact "batch" for l2.
            // while "headers" in the "block"(usually single tx) for l2.
            // But to reduce the code conflicts with upstream, we still use the name `block`
            block: Block {
                headers: headers
                    .iter()
                    .map(|b| (b.number.as_u64(), b.clone()))
                    .collect::<BTreeMap<_, _>>(),
                ..Default::default()
            },
            block_ctx: BlockContext::new(),
        }
    }

    /// Obtain a mutable reference to the state that the `CircuitInputBuilder`
    /// maintains, contextualized to a particular transaction and a
    /// particular execution step in that transaction.
    pub fn state_ref(
        &'a mut self,
        tx: &'a mut Transaction,
        tx_ctx: &'a mut TransactionContext,
    ) -> CircuitInputStateRef {
        CircuitInputStateRef {
            sdb: &mut self.sdb,
            code_db: &mut self.code_db,
            block: &mut self.block,
            block_ctx: &mut self.block_ctx,
            tx,
            tx_ctx,
        }
    }

    /// Create a new Transaction from a [`eth_types::Transaction`].
    pub fn new_tx(
        &mut self,
        eth_tx: &eth_types::Transaction,
        is_success: bool,
    ) -> Result<Transaction, Error> {
        let call_id = self.block_ctx.rwc.0;

        self.block_ctx.call_map.insert(
            call_id,
            (
                eth_tx
                    .transaction_index
                    .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                    .as_u64() as usize,
                0,
            ),
        );

        Transaction::new(
            call_id,
            &mut self.sdb,
            &mut self.code_db,
            eth_tx,
            is_success,
        )
    }

    /// Iterate over all generated CallContext RwCounterEndOfReversion
    /// operations and set the correct value. This is required because when we
    /// generate the RwCounterEndOfReversion operation in
    /// `gen_associated_ops` we don't know yet which value it will take,
    /// so we put a placeholder; so we do it here after the values are known.
    pub fn set_value_ops_call_context_rwc_eor(&mut self) {
        for oper in self.block.container.call_context.iter_mut() {
            let op = oper.op_mut();
            if matches!(op.field, CallContextField::RwCounterEndOfReversion) {
                let (tx_idx, call_idx) = self
                    .block_ctx
                    .call_map
                    .get(&op.call_id)
                    .expect("call_id not found in call_map");
                op.value = self.block.txs[*tx_idx].calls()[*call_idx]
                    .rw_counter_end_of_reversion
                    .into();
            }
        }
    }

    /// Handle a block by handling each transaction to generate all the
    /// associated operations.
    pub fn handle_block(
        &mut self,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<(), Error> {
        self.handle_block_inner(eth_block, geth_traces, true, true)
    }
    /// Handle a block by handling each transaction to generate all the
    /// associated operations.
    pub fn handle_block_inner(
        &mut self,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
        handle_rwc_reversion: bool,
        check_last_tx: bool,
    ) -> Result<(), Error> {
        // accumulates gas across all txs in the block
        log::info!("handling block {:?}", eth_block.number);
        for (tx_index, tx) in eth_block.transactions.iter().enumerate() {
            let geth_trace = &geth_traces[tx_index];
            if geth_trace.struct_logs.is_empty() {
                // only update state
                self.sdb.increase_nonce(&tx.from);
                let (_, to_acc) = self.sdb.get_account_mut(&tx.to.unwrap());
                to_acc.balance += tx.value;
                let (_, from_acc) = self.sdb.get_account_mut(&tx.from);
                if let Some(mint) = eth_types::geth_types::Transaction::get_mint(tx) {
                    #[cfg(feature = "kanvas")]
                    debug_assert_eq!(tx.transaction_type.unwrap().as_u64(), DEPOSIT_TX_TYPE);
                    from_acc.balance += mint;
                    log::trace!("mint to {} value {}", tx.from, mint);
                }
                from_acc.balance -= tx.value;
                let gas_cost = U256::from(geth_trace.gas.0) * tx.gas_price.unwrap();
                debug_assert!(
                    from_acc.balance >= gas_cost,
                    "pay gas failed. tx {:?}, from_acc {:?}",
                    tx,
                    from_acc
                );
                from_acc.balance -= gas_cost;
                log::trace!(
                    "native transfer: from {} to {}, value {} fee {}",
                    tx.from,
                    tx.to.unwrap(),
                    tx.value,
                    gas_cost
                );

                #[cfg(feature = "kanvas")]
                if tx.transaction_type.is_none()
                    || tx.transaction_type.unwrap().as_u64() != DEPOSIT_TX_TYPE
                {
                    let base_fee =
                        U256::from(geth_trace.gas.0) * eth_block.base_fee_per_gas.unwrap();
                    let (_, base_fee_recipient_account) =
                        self.sdb.get_account_mut(&BASE_FEE_RECIPIENT);
                    base_fee_recipient_account.balance += base_fee;
                    log::trace!("collect base fee: value {}", base_fee);

                    let (l1_base_fee, l1_fee_overhead, l1_fee_scalar) = self.sdb.get_l1_block()?;
                    let rollup_data_gas_cost =
                        eth_types::geth_types::Transaction::compute_rollup_data_gas_cost(tx);
                    let l1_fee = self.sdb.compute_l1_fee(
                        l1_base_fee,
                        l1_fee_overhead,
                        l1_fee_scalar,
                        rollup_data_gas_cost,
                    )?;
                    let (_, l1_fee_recipient_account) = self.sdb.get_account_mut(&L1_FEE_RECIPIENT);
                    l1_fee_recipient_account.balance += l1_fee;
                    log::trace!("collect l1 fee: value {}", l1_fee);
                }
                continue;
            }
            log::info!(
                "handling {}th(inner idx: {}) tx {:?}",
                tx.transaction_index.unwrap_or_default(),
                self.block.txs.len(),
                tx.hash
            );
            let mut tx = tx.clone();
            tx.transaction_index = Some(self.block.txs.len().into());
            self.handle_tx(
                &tx,
                geth_trace,
                check_last_tx && tx_index + 1 == eth_block.transactions.len(),
            )?;
        }
        if handle_rwc_reversion {
            self.set_value_ops_call_context_rwc_eor();
        }
        Ok(())
    }

    /// Handle a transaction with its corresponding execution trace to generate
    /// all the associated operations.  Each operation is registered in
    /// `self.block.container`, and each step stores the
    /// [`OperationRef`](crate::exec_trace::OperationRef) to each of the
    /// generated operations.
    fn handle_tx(
        &mut self,
        eth_tx: &eth_types::Transaction,
        geth_trace: &GethExecTrace,
        is_last_tx: bool,
    ) -> Result<(), Error> {
        let mut tx = self.new_tx(eth_tx, !geth_trace.failed)?;
        let mut tx_ctx = TransactionContext::new(eth_tx, geth_trace, is_last_tx)?;
        let mut debug_tx = tx.clone();
        debug_tx.input.clear();
        log::trace!("handle_tx tx {:?}", debug_tx);
        if let Some(al) = &eth_tx.access_list {
            for item in &al.0 {
                self.sdb.add_account_to_access_list(item.address);
                for k in &item.storage_keys {
                    self.sdb
                        .add_account_storage_to_access_list((item.address, (*k).to_word()));
                }
            }
        }
        // TODO: Move into gen_associated_steps with
        // - execution_state: BeginTx
        // - op: None
        // Generate BeginTx step
        let mut begin_tx_step = gen_begin_tx_ops(&mut self.state_ref(&mut tx, &mut tx_ctx))?;
        begin_tx_step.gas_cost = GasCost(tx.gas - geth_trace.struct_logs[0].gas.0);
        log::trace!("begin_tx_step {:?}", begin_tx_step);
        tx.steps_mut().push(begin_tx_step);

        for (index, geth_step) in geth_trace.struct_logs.iter().enumerate() {
            let mut state_ref = self.state_ref(&mut tx, &mut tx_ctx);
            log::trace!(
                "handle {}th tx depth {} {}th opcode {:?} pc: {} gas_left: {} rwc: {} call_id: {} args: {}",
                eth_tx.transaction_index.unwrap_or_default(),
                geth_step.depth,
                index,
                geth_step.op,
                geth_step.pc.0,
                geth_step.gas.0,
                state_ref.block_ctx.rwc.0,
                state_ref.call().map(|c| c.call_id).unwrap_or(0),
                if geth_step.op.is_push() {
                    match geth_step.stack.last() {
                        Ok(w) => format!("{:?}", w),
                        Err(_) => "".to_string(),
                    }
                } else if geth_step.op.is_call6() {
                    format!(
                        "{:?} {:40x} {:?} {:?} {:?} {:?}",
                        geth_step.stack.nth_last(0),
                        geth_step.stack.nth_last(1).unwrap(),
                        geth_step.stack.nth_last(2),
                        geth_step.stack.nth_last(3),
                        geth_step.stack.nth_last(4),
                        geth_step.stack.nth_last(5)
                    )
                } else if geth_step.op.is_call7() {
                    format!(
                        "{:?} {:40x} {:?} {:?} {:?} {:?} {:?}",
                        geth_step.stack.nth_last(0),
                        geth_step.stack.nth_last(1).unwrap(),
                        geth_step.stack.nth_last(2),
                        geth_step.stack.nth_last(3),
                        geth_step.stack.nth_last(4),
                        geth_step.stack.nth_last(5),
                        geth_step.stack.nth_last(6),
                    )
                } else {
                    "".to_string()
                }
            );
            let exec_steps = gen_associated_ops(
                &geth_step.op,
                &mut state_ref,
                &geth_trace.struct_logs[index..],
            )?;
            tx.steps_mut().extend(exec_steps);
        }

        // TODO: Move into gen_associated_steps with
        // - execution_state: EndTx, EndDepositTx
        // - op: None
        // Generate EndTx / EndDepositTx step
        if tx.is_deposit() {
            #[cfg(feature = "kanvas")]
            let end_deposit_tx_step =
                gen_end_deposit_tx_ops(&mut self.state_ref(&mut tx, &mut tx_ctx))?;
            #[cfg(feature = "kanvas")]
            tx.steps_mut().push(end_deposit_tx_step);
        } else {
            #[cfg(feature = "kanvas")]
            let fee_hook_steps = gen_fee_hook_ops(&mut self.state_ref(&mut tx, &mut tx_ctx))?;
            #[cfg(feature = "kanvas")]
            tx.steps_mut().extend(fee_hook_steps);

            let end_tx_step = gen_end_tx_ops(&mut self.state_ref(&mut tx, &mut tx_ctx))?;
            tx.steps_mut().push(end_tx_step);
        }

        self.sdb.commit_tx();
        self.block.txs.push(tx);

        Ok(())
    }

    /// Return all the keccak inputs used during the processing of the current
    /// block.
    pub fn keccak_inputs(&self) -> Result<Vec<Vec<u8>>, Error> {
        let mut keccak_inputs = Vec::new();
        // Tx Circuit
        let txs: Vec<geth_types::Transaction> = self.block.txs.iter().map(|tx| tx.into()).collect();
        keccak_inputs.extend_from_slice(&keccak_inputs_tx_circuit(
            &txs,
            self.block.chain_id().as_u64(),
        )?);
        // Bytecode Circuit
        for bytecode in self.code_db.0.values() {
            keccak_inputs.push(bytecode.clone());
        }
        // EVM Circuit
        keccak_inputs.extend_from_slice(&self.block.sha3_inputs);
        // MPT Circuit
        // TODO https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/696
        Ok(keccak_inputs)
    }
}

/// Generate the keccak inputs required by the SignVerify Chip from the
/// signature datas.
pub fn keccak_inputs_sign_verify(sigs: &[SignData]) -> Vec<Vec<u8>> {
    let mut inputs = Vec::new();
    for sig in sigs {
        let pk_le = pk_bytes_le(&sig.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        inputs.push(pk_be.to_vec());
    }
    // Padding signature
    let pk_le = pk_bytes_le(&SignData::default().pk);
    let pk_be = pk_bytes_swap_endianness(&pk_le);
    inputs.push(pk_be.to_vec());
    inputs
}

/// Generate the keccak inputs required by the Tx Circuit from the transactions.
pub fn keccak_inputs_tx_circuit(
    txs: &[geth_types::Transaction],
    chain_id: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut inputs = Vec::new();
    let sign_datas: Vec<SignData> = txs.iter().map(|tx| tx.sign_data(chain_id)).try_collect()?;
    // Keccak inputs from SignVerify Chip
    let sign_verify_inputs = keccak_inputs_sign_verify(&sign_datas);
    inputs.extend_from_slice(&sign_verify_inputs);
    // NOTE: We don't verify the Tx Hash in the circuit yet, so we don't have more
    // hash inputs.
    Ok(inputs)
}

/// Retrieve the init_code from memory for {CREATE, CREATE2}
pub fn get_create_init_code<'a, 'b>(
    call_ctx: &'a CallContext,
    step: &'b GethExecStep,
) -> Result<&'a [u8], Error> {
    let offset = step.stack.nth_last(1)?;
    let length = step.stack.nth_last(2)?;
    Ok(&call_ctx.memory.0
        [offset.low_u64() as usize..(offset.low_u64() + length.low_u64()) as usize])
}

/// Retrieve the memory offset and length of call.
pub fn get_call_memory_offset_length(step: &GethExecStep, nth: usize) -> Result<(u64, u64), Error> {
    let offset = step.stack.nth_last(nth)?;
    let length = step.stack.nth_last(nth + 1)?;
    if length.is_zero() {
        Ok((0, 0))
    } else {
        Ok((offset.low_u64(), length.low_u64()))
    }
}

type EthBlock = eth_types::Block<eth_types::Transaction>;

/// Struct that wraps a GethClient and contains methods to perform all the steps
/// necessary to generate the circuit inputs for a block by querying geth for
/// the necessary information and using the CircuitInputBuilder.
pub struct BuilderClient<P: JsonRpcClient> {
    cli: GethClient<P>,
    chain_id: Word,
    history_hashes: Vec<Word>,
}

impl<P: JsonRpcClient> BuilderClient<P> {
    /// Create a new BuilderClient
    pub async fn new(client: GethClient<P>) -> Result<Self, Error> {
        let chain_id = client.get_chain_id().await?;

        Ok(Self {
            cli: client,
            chain_id: chain_id.into(),
            // TODO: Get history hashes
            history_hashes: Vec::new(),
        })
    }

    /// Step 1. Query geth for Block, Txs and TxExecTraces
    pub async fn get_block(
        &self,
        block_num: u64,
    ) -> Result<(EthBlock, Vec<eth_types::GethExecTrace>), Error> {
        let eth_block = self.cli.get_block_by_number(block_num.into()).await?;
        let geth_traces = self.cli.trace_block_by_number(block_num.into()).await?;

        Ok((eth_block, geth_traces))
    }

    /// Step 2. Get State Accesses from TxExecTraces
    pub fn get_state_accesses(
        &self,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<Vec<Access>, Error> {
        let mut block_access_trace = vec![Access::new(
            None,
            RW::WRITE,
            AccessValue::Account {
                address: eth_block
                    .author
                    .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?,
            },
        )];
        for (tx_index, tx) in eth_block.transactions.iter().enumerate() {
            let geth_trace = &geth_traces[tx_index];
            let tx_access_trace = gen_state_access_trace(eth_block, tx, geth_trace)?;
            block_access_trace.extend(tx_access_trace);
        }

        Ok(block_access_trace)
    }

    /// Step 3. Query geth for all accounts, storage keys, and codes from
    /// Accesses
    pub async fn get_state(
        &self,
        block_num: u64,
        access_set: AccessSet,
    ) -> Result<
        (
            Vec<eth_types::EIP1186ProofResponse>,
            HashMap<Address, Vec<u8>>,
        ),
        Error,
    > {
        let mut proofs = Vec::new();
        for (address, key_set) in access_set.state {
            let mut keys: Vec<Word> = key_set.iter().cloned().collect();
            keys.sort();
            let proof = self
                .cli
                .get_proof(address, keys, (block_num - 1).into())
                .await
                .unwrap();
            proofs.push(proof);
        }
        let mut codes: HashMap<Address, Vec<u8>> = HashMap::new();
        for address in access_set.code {
            let code = self
                .cli
                .get_code(address, (block_num - 1).into())
                .await
                .unwrap();
            codes.insert(address, code);
        }
        Ok((proofs, codes))
    }

    /// Step 4. Build a partial StateDB from step 3
    pub fn build_state_code_db(
        &self,
        proofs: Vec<eth_types::EIP1186ProofResponse>,
        codes: HashMap<Address, Vec<u8>>,
    ) -> (StateDB, CodeDB) {
        let mut sdb = StateDB::new();
        for proof in proofs {
            let mut storage = HashMap::new();
            for storage_proof in proof.storage_proof {
                storage.insert(storage_proof.key, storage_proof.value);
            }
            sdb.set_account(
                &proof.address,
                state_db::Account {
                    nonce: proof.nonce,
                    balance: proof.balance,
                    storage,
                    code_hash: proof.code_hash,
                },
            )
        }

        let mut code_db = CodeDB::new();
        for (_address, code) in codes {
            code_db.insert(code.clone());
        }
        (sdb, code_db)
    }

    /// Step 5. For each step in TxExecTraces, gen the associated ops and state
    /// circuit inputs
    pub fn gen_inputs_from_state(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<CircuitInputBuilder, Error> {
        let block = BlockHead::new(self.chain_id, self.history_hashes.clone(), eth_block)?;
        let mut builder = CircuitInputBuilder::new(sdb, code_db, &[block]);
        builder.handle_block(eth_block, geth_traces)?;
        Ok(builder)
    }

    /// Step 5. For each step in TxExecTraces, gen the associated ops and state
    /// circuit inputs
    pub fn gen_inputs_from_state_multi(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        blocks_and_traces: &[(EthBlock, Vec<eth_types::GethExecTrace>)],
    ) -> Result<CircuitInputBuilder, Error> {
        let mut builder = CircuitInputBuilder::new(sdb, code_db, Default::default());
        for (idx, (eth_block, geth_traces)) in blocks_and_traces.iter().enumerate() {
            let is_last = idx == blocks_and_traces.len() - 1;
            let header = BlockHead::new(self.chain_id, self.history_hashes.clone(), eth_block)?;
            builder.block.headers.insert(header.number.as_u64(), header);
            builder.handle_block_inner(eth_block, geth_traces, is_last, is_last)?;
        }
        Ok(builder)
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs(
        &self,
        block_num: u64,
    ) -> Result<
        (
            CircuitInputBuilder,
            eth_types::Block<eth_types::Transaction>,
        ),
        Error,
    > {
        let (eth_block, geth_traces) = self.get_block(block_num).await?;
        let access_set = self.get_state_accesses(&eth_block, &geth_traces)?;
        let (proofs, codes) = self.get_state(block_num, access_set.into()).await?;
        let (state_db, code_db) = self.build_state_code_db(proofs, codes);
        let builder = self.gen_inputs_from_state(state_db, code_db, &eth_block, &geth_traces)?;
        Ok((builder, eth_block))
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs_multi_blocks(
        &self,
        block_num_begin: u64,
        block_num_end: u64,
    ) -> Result<CircuitInputBuilder, Error> {
        let mut blocks_and_traces = Vec::new();
        let mut access_set = AccessSet::default();
        for block_num in block_num_begin..block_num_end {
            let (eth_block, geth_traces) = self.get_block(block_num).await?;
            let access_list = self.get_state_accesses(&eth_block, &geth_traces)?;
            access_set.add(access_list);
            blocks_and_traces.push((eth_block, geth_traces));
        }
        let (proofs, codes) = self.get_state(block_num_begin, access_set).await?;
        let (state_db, code_db) = self.build_state_code_db(proofs, codes);
        let builder = self.gen_inputs_from_state_multi(state_db, code_db, &blocks_and_traces)?;
        Ok(builder)
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs_tx(&self, hash_str: &str) -> Result<CircuitInputBuilder, Error> {
        let mut hash: [u8; 32] = [0; 32];
        let hash_str = if &hash_str[0..2] == "0x" {
            &hash_str[2..]
        } else {
            hash_str
        };
        decode_to_slice(hash_str, &mut hash).unwrap();
        let tx_hash = H256::from(hash);

        let mut tx: eth_types::Transaction = self.cli.get_tx_by_hash(tx_hash).await?;
        tx.transaction_index = Some(0.into());
        let geth_traces = self.cli.trace_tx_by_hash(tx_hash).await?;
        let mut eth_block = self
            .cli
            .get_block_by_number(tx.block_number.unwrap().into())
            .await?;

        eth_block.transactions = vec![tx.clone()];

        let mut block_access_trace = vec![Access::new(
            None,
            RW::WRITE,
            AccessValue::Account {
                address: eth_block.author.unwrap(),
            },
        )];
        let geth_trace = &geth_traces[0];
        let tx_access_trace = gen_state_access_trace(
            &eth_types::Block::<eth_types::Transaction>::default(),
            &tx,
            geth_trace,
        )?;
        block_access_trace.extend(tx_access_trace);

        let access_set = AccessSet::from(block_access_trace);

        let (proofs, codes) = self
            .get_state(tx.block_number.unwrap().as_u64(), access_set)
            .await?;
        let (state_db, code_db) = self.build_state_code_db(proofs, codes);
        let builder = self.gen_inputs_from_state(state_db, code_db, &eth_block, &geth_traces)?;
        Ok(builder)
    }
}
