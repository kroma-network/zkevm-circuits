#[cfg(feature = "kanvas")]
use crate::evm_circuit::util::{common_gadget::UpdateBalanceGadget, math_gadget::IsEqualGadget};
use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::TransferWithGasFeeGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{MulWordByU64Gadget, RangeCheckGadget},
            CachedRegion, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag, TxFieldTag as TxContextFieldTag},
    util::Expr,
};
use eth_types::{evm_types::rwc_util::begin_tx_rwc_offset, Field, ToLittleEndian, ToScalar, U256};
#[cfg(feature = "kanvas")]
use eth_types::{evm_types::rwc_util::BEGIN_TX_MINT_RWC_OFFSET, geth_types::DEPOSIT_TX_TYPE};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct BeginTxGadget<F> {
    tx_id: Cell<F>,
    tx_type: Cell<F>,
    tx_nonce: Cell<F>,
    tx_gas: Cell<F>,
    tx_gas_price: Word<F>,
    #[cfg(feature = "kanvas")]
    mint: UpdateBalanceGadget<F, 2, true>,
    mul_gas_fee_by_gas: MulWordByU64Gadget<F>,
    tx_caller_address: Cell<F>,
    tx_callee_address: Cell<F>,
    tx_is_create: Cell<F>,
    tx_value: Word<F>,
    #[cfg(feature = "kanvas")]
    tx_mint: Word<F>,
    tx_call_data_length: Cell<F>,
    tx_call_data_gas_cost: Cell<F>,
    reversion_info: ReversionInfo<F>,
    intrinsic_gas_cost: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, N_BYTES_GAS>,
    transfer_with_gas_fee: TransferWithGasFeeGadget<F>,
    code_hash: Cell<F>,
    #[cfg(feature = "kanvas")]
    is_deposit_tx: IsEqualGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for BeginTxGadget<F> {
    const NAME: &'static str = "BeginTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BeginTx;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id = cb.curr.state.rw_counter.clone();

        let tx_id = cb.query_cell();
        cb.call_context_lookup(
            1.expr(),
            Some(call_id.expr()),
            CallContextFieldTag::TxId,
            tx_id.expr(),
        );
        let mut reversion_info = cb.reversion_info_write(None);
        cb.call_context_lookup(
            1.expr(),
            Some(call_id.expr()),
            CallContextFieldTag::IsSuccess,
            reversion_info.is_persistent(),
        );

        let [tx_type, tx_nonce, tx_gas, tx_caller_address, tx_callee_address, tx_is_create, tx_call_data_length, tx_call_data_gas_cost] =
            [
                TxContextFieldTag::Type,
                TxContextFieldTag::Nonce,
                TxContextFieldTag::Gas,
                TxContextFieldTag::CallerAddress,
                TxContextFieldTag::CalleeAddress,
                TxContextFieldTag::IsCreate,
                TxContextFieldTag::CallDataLength,
                TxContextFieldTag::CallDataGasCost,
            ]
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));
        let [tx_gas_price, tx_value] = [TxContextFieldTag::GasPrice, TxContextFieldTag::Value]
            .map(|field_tag| cb.tx_context_as_word(tx_id.expr(), field_tag, None));
        #[cfg(feature = "kanvas")]
        let tx_mint = cb.tx_context_as_word(tx_id.expr(), TxContextFieldTag::Mint, None);

        // Add first step constraint to have both rw_counter and tx_id to be 1
        cb.add_constraint_first_step(
            "rw_counter is initialized to be 1",
            1.expr() - cb.curr.state.rw_counter.expr(),
        );
        cb.add_constraint_first_step("tx_id is initialized to be 1", 1.expr() - tx_id.expr());

        // Add mint to caller's balance.
        #[cfg(feature = "kanvas")]
        let is_deposit_tx = IsEqualGadget::construct(cb, tx_type.expr(), DEPOSIT_TX_TYPE.expr());
        #[cfg(not(feature = "kanvas"))]
        let is_deposit_tx = 0.expr();
        #[cfg(feature = "kanvas")]
        let mint = UpdateBalanceGadget::construct(
            cb,
            tx_caller_address.expr(),
            vec![tx_mint.clone()],
            None,
            Some(is_deposit_tx.expr()),
        );

        // Increase caller's nonce.
        // (tx caller's nonce always increases even tx ends with error)
        cb.account_write(
            tx_caller_address.expr(),
            AccountFieldTag::Nonce,
            tx_nonce.expr() + 1.expr(),
            tx_nonce.expr(),
            None,
        );

        // TODO: Implement EIP 1559 (currently it only supports legacy
        // transaction format)
        // Calculate transaction gas fee
        let mul_gas_fee_by_gas =
            MulWordByU64Gadget::construct(cb, tx_gas_price.clone(), tx_gas.expr());

        // TODO: Take gas cost of access list (EIP 2930) into consideration.
        // Use intrinsic gas
        /*
        let intrinsic_gas_cost = select::expr(
            tx_is_create.expr(),
            GasCost::CREATION_TX.expr(),
            GasCost::TX.expr(),
        ) + tx_call_data_gas_cost.expr();
        */
        // Check gas_left is sufficient
        let intrinsic_gas_cost = cb.query_cell();
        let gas_left = tx_gas.expr() - intrinsic_gas_cost.expr();
        let sufficient_gas_left = RangeCheckGadget::construct(cb, gas_left.clone());

        // Prepare access list of caller and callee
        cb.account_access_list_write(
            tx_id.expr(),
            tx_caller_address.expr(),
            1.expr(),
            0.expr(),
            None,
        );
        cb.account_access_list_write(
            tx_id.expr(),
            tx_callee_address.expr(),
            1.expr(),
            0.expr(),
            None,
        );

        // Transfer value from caller to callee
        let transfer_with_gas_fee = TransferWithGasFeeGadget::construct(
            cb,
            tx_caller_address.expr(),
            tx_callee_address.expr(),
            tx_value.clone(),
            mul_gas_fee_by_gas.product().clone(),
            &mut reversion_info,
        );

        // TODO: Handle creation transaction
        // TODO: Handle precompiled

        // Read code_hash of callee
        let code_hash = cb.query_cell();
        cb.account_write(
            tx_callee_address.expr(),
            AccountFieldTag::CodeHash,
            code_hash.expr(),
            code_hash.expr(),
            None,
        );

        // Setup first call's context.
        for (field_tag, value) in [
            (CallContextFieldTag::Depth, 1.expr()),
            (CallContextFieldTag::CallerAddress, tx_caller_address.expr()),
            (CallContextFieldTag::CalleeAddress, tx_callee_address.expr()),
            (CallContextFieldTag::CallDataOffset, 0.expr()),
            (
                CallContextFieldTag::CallDataLength,
                tx_call_data_length.expr(),
            ),
            (CallContextFieldTag::Value, tx_value.expr()),
            (CallContextFieldTag::IsStatic, 0.expr()),
            (CallContextFieldTag::LastCalleeId, 0.expr()),
            (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
            (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
            (CallContextFieldTag::IsRoot, 1.expr()),
            (CallContextFieldTag::IsCreate, tx_is_create.expr()),
            (CallContextFieldTag::CodeHash, code_hash.expr()),
        ] {
            cb.call_context_lookup(true.expr(), Some(call_id.expr()), field_tag, value);
        }

        cb.require_step_state_transition(StepStateTransition {
            // 23 reads and writes + 1 writes if transaction is a deposit tx:
            //   - Write CallContext TxId
            //   - Write CallContext RwCounterEndOfReversion
            //   - Write CallContext IsPersistent
            //   - Write CallContext IsSuccess
            //   - (If tx is a deposit tx) Write Account Balance
            //   - Write Account Nonce
            //   - Write TxAccessListAccount
            //   - Write TxAccessListAccount
            //   - Write Account Balance
            //   - Write Account Balance
            //   - Read Account CodeHash
            //   - Write CallContext Depth
            //   - Write CallContext CallerAddress
            //   - Write CallContext CalleeAddress
            //   - Write CallContext CallDataOffset
            //   - Write CallContext CallDataLength
            //   - Write CallContext Value
            //   - Write CallContext IsStatic
            //   - Write CallContext LastCalleeId
            //   - Write CallContext LastCalleeReturnDataOffset
            //   - Write CallContext LastCalleeReturnDataLength
            //   - Write CallContext IsRoot
            //   - Write CallContext IsCreate
            //   - Write CallContext CodeHash
            rw_counter: Delta(23.expr() + is_deposit_tx.expr()),
            call_id: To(call_id.expr()),
            is_root: To(true.expr()),
            is_create: To(tx_is_create.expr()),
            code_hash: To(code_hash.expr()),
            gas_left: To(gas_left),
            reversible_write_counter: To(2.expr()),
            log_id: To(0.expr()),
            ..StepStateTransition::new_context()
        });

        Self {
            tx_id,
            tx_type,
            tx_nonce,
            tx_gas,
            tx_gas_price,
            #[cfg(feature = "kanvas")]
            mint,
            mul_gas_fee_by_gas,
            tx_caller_address,
            tx_callee_address,
            tx_is_create,
            tx_value,
            #[cfg(feature = "kanvas")]
            tx_mint,
            tx_call_data_length,
            tx_call_data_gas_cost,
            reversion_info,
            sufficient_gas_left,
            transfer_with_gas_fee,
            code_hash,
            intrinsic_gas_cost,
            #[cfg(feature = "kanvas")]
            is_deposit_tx,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let gas_fee = tx.gas_price * tx.gas;

        let callee_addr = call.callee_address; // block.rws[step.rw_indices[5]].tx_access_list_value_pair();
        let mut _mint_balance = U256::zero();
        let mut _mint_balance_prev = U256::zero();

        #[cfg(feature = "kanvas")]
        if tx.is_deposit() {
            (_mint_balance, _mint_balance_prev) =
                block.rws[step.rw_indices[BEGIN_TX_MINT_RWC_OFFSET]].account_value_pair();
        }

        let [caller_balance_pair, callee_balance_pair, (callee_code_hash, _)] =
            [7, 8, 9].map(|idx| {
                block.rws[step.rw_indices[begin_tx_rwc_offset(tx.transaction_type, idx)]]
                    .account_value_pair()
            });

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.tx_type
            .assign(region, offset, Value::known(F::from(tx.transaction_type)))?;
        self.tx_nonce
            .assign(region, offset, Value::known(F::from(tx.nonce)))?;
        self.tx_gas
            .assign(region, offset, Value::known(F::from(tx.gas)))?;
        self.tx_gas_price
            .assign(region, offset, Some(tx.gas_price.to_le_bytes()))?;
        self.tx_value
            .assign(region, offset, Some(tx.value.to_le_bytes()))?;
        #[cfg(feature = "kanvas")]
        self.tx_mint
            .assign(region, offset, Some(tx.mint.to_le_bytes()))?;
        #[cfg(feature = "kanvas")]
        self.mint.assign(
            region,
            offset,
            _mint_balance_prev,
            vec![tx.mint],
            _mint_balance,
        )?;
        self.mul_gas_fee_by_gas
            .assign(region, offset, tx.gas_price, tx.gas, gas_fee)?;
        self.tx_caller_address.assign(
            region,
            offset,
            Value::known(
                tx.caller_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.tx_callee_address.assign(
            region,
            offset,
            Value::known(
                callee_addr
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.tx_is_create
            .assign(region, offset, Value::known(F::from(tx.is_create as u64)))?;

        let call_data_length = block.rws
            [step.rw_indices[begin_tx_rwc_offset(tx.transaction_type, 14)]]
        .call_context_value()
        .as_u64();
        self.tx_call_data_length.assign(
            region,
            offset,
            Value::known(F::from(call_data_length as u64)),
        )?;
        self.tx_call_data_gas_cost.assign(
            region,
            offset,
            Value::known(F::from(tx.call_data_gas_cost)),
        )?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.intrinsic_gas_cost
            .assign(region, offset, Value::known(F::from(step.gas_cost)))?;
        self.sufficient_gas_left
            .assign(region, offset, F::from(tx.gas - step.gas_cost))?;
        self.transfer_with_gas_fee.assign(
            region,
            offset,
            caller_balance_pair,
            callee_balance_pair,
            tx.value,
            gas_fee,
        )?;
        self.code_hash.assign(
            region,
            offset,
            Value::known(RandomLinearCombination::random_linear_combine(
                callee_code_hash.to_le_bytes(),
                block.randomness,
            )),
        )?;
        #[cfg(feature = "kanvas")]
        self.is_deposit_tx.assign(
            region,
            offset,
            F::from(tx.transaction_type),
            F::from(DEPOSIT_TX_TYPE),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_bytes, run_test_circuit},
        witness::block_convert,
    };
    use bus_mapping::{evm::OpcodeId, mock::BlockData};
    use eth_types::{self, bytecode, evm_types::GasCost, geth_types::GethData, Word};
    use mock::{
        eth, gwei, test_ctx::helpers::account_0_code_account_1_no_code, tx_idx, SimpleTestContext,
        MOCK_ACCOUNTS,
    };
    #[cfg(feature = "kanvas")]
    use mock::{
        test_ctx::helpers::{setup_kanvas_required_accounts, system_deposit_tx},
        TestContext,
    };

    fn gas(call_data: &[u8]) -> Word {
        Word::from(
            GasCost::TX.as_u64()
                + 2 * OpcodeId::PUSH32.constant_gas_cost().as_u64()
                + call_data
                    .iter()
                    .map(|&x| if x == 0 { 4 } else { 16 })
                    .sum::<u64>(),
        )
    }

    fn test_ok(tx: eth_types::Transaction, is_success: bool) {
        let code = if is_success {
            bytecode! {
                PUSH1(0)
                PUSH1(0)
                RETURN
            }
        } else {
            bytecode! {
                PUSH1(0)
                PUSH1(0)
                REVERT
            }
        };

        // Get the execution steps from the external tracer
        let block: GethData = SimpleTestContext::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, _accs| {
                #[cfg(feature = "kanvas")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)]
                    .to(tx.to.unwrap())
                    .from(tx.from)
                    .gas_price(tx.gas_price.unwrap())
                    .gas(tx.gas)
                    .input(tx.input)
                    .value(tx.value);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();

        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db);
        assert_eq!(run_test_circuit(block), Ok(()));
    }

    fn mock_tx(value: Word, gas_price: Word, calldata: Vec<u8>) -> eth_types::Transaction {
        let from = MOCK_ACCOUNTS[1];
        let to = MOCK_ACCOUNTS[0];
        eth_types::Transaction {
            from,
            to: Some(to),
            value,
            gas: gas(&calldata),
            gas_price: Some(gas_price),
            input: calldata.into(),
            ..Default::default()
        }
    }

    #[test]
    fn begin_tx_gadget_simple() {
        // Transfer 1 ether, successfully
        test_ok(mock_tx(eth(1), gwei(2), vec![]), true);

        // Transfer 1 ether, tx reverts
        test_ok(mock_tx(eth(1), gwei(2), vec![]), false);

        // Transfer nothing with some calldata
        test_ok(
            mock_tx(eth(0), gwei(2), vec![1, 2, 3, 4, 0, 0, 0, 0]),
            false,
        );
    }

    #[test]
    fn begin_tx_large_nonce() {
        // This test checks that the rw table assignment and evm circuit are consistent
        // in not applying an RLC to account and tx nonces.
        // https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/592
        let multibyte_nonce = Word::from(700);

        let to = MOCK_ACCOUNTS[0];
        let from = MOCK_ACCOUNTS[1];

        let code = bytecode! {
            STOP
        };

        let block: GethData = SimpleTestContext::new(
            None,
            #[allow(unused_mut)]
            |mut accs| {
                accs[0].address(to).balance(eth(1)).code(code);
                accs[1].address(from).balance(eth(1)).nonce(multibyte_nonce);
                #[cfg(feature = "kanvas")]
                setup_kanvas_required_accounts(accs.as_mut_slice(), 2);
            },
            |mut txs, _| {
                #[cfg(feature = "kanvas")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)].to(to).from(from).nonce(multibyte_nonce);
            },
            |block, _| block,
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db);

        assert_eq!(run_test_circuit(block), Ok(()));
    }

    #[test]
    fn begin_tx_gadget_rand() {
        let random_amount = Word::from_little_endian(&rand_bytes(32)) % eth(1);
        let random_gas_price = Word::from_little_endian(&rand_bytes(32)) % gwei(2);
        // If this test fails, we want these values to appear in the CI logs.
        dbg!(random_amount, random_gas_price);

        // Transfer random ether, successfully
        test_ok(mock_tx(random_amount, gwei(2), vec![]), true);

        // Transfer nothing with random gas_price, successfully
        test_ok(mock_tx(eth(0), random_gas_price, vec![]), true);

        // Transfer random ether, tx reverts
        test_ok(mock_tx(random_amount, gwei(2), vec![]), false);

        // Transfer nothing with random gas_price, tx reverts
        test_ok(mock_tx(eth(0), random_gas_price, vec![]), false);
    }

    #[cfg(feature = "kanvas")]
    #[test]
    fn begin_tx_gadget_deposit() {
        declare_test_context!(TestContext2_2, 2, 2);
        // Get the execution steps from the external tracer
        use eth_types::geth_types::DEPOSIT_TX_TYPE;
        use mock::declare_test_context;
        let block: GethData = TestContext2_2::new(
            None,
            account_0_code_account_1_no_code(bytecode! { STOP }),
            |mut txs, accs| {
                #[cfg(feature = "kanvas")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .transaction_type(DEPOSIT_TX_TYPE);
                txs[tx_idx!(1)]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .transaction_type(DEPOSIT_TX_TYPE)
                    .mint(eth(1));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();

        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db);
        assert_eq!(run_test_circuit(block), Ok(()));
    }
}
