use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    evm::Opcode,
    operation::{AccountField, CallContextField, TxAccessListAccountOp},
    Error,
};
use eth_types::{GethExecStep, ToAddress, ToWord, H256};

#[derive(Debug, Copy, Clone)]
pub(crate) struct Extcodesize;

impl Opcode for Extcodesize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // Read account address from stack.
        let address_word = geth_step.stack.last()?;
        let address = address_word.to_address();
        state.stack_read(&mut exec_step, geth_step.stack.last_filled(), address_word)?;

        // Read transaction ID, rw_counter_end_of_reversion, and is_persistent from call
        // context.
        for (field, value) in [
            (CallContextField::TxId, state.tx_ctx.id().to_word()),
            (
                CallContextField::RwCounterEndOfReversion,
                state.call()?.rw_counter_end_of_reversion.to_word(),
            ),
            (
                CallContextField::IsPersistent,
                state.call()?.is_persistent.to_word(),
            ),
        ] {
            state.call_context_read(&mut exec_step, state.call()?.call_id, field, value);
        }

        // Update transaction access list for account address.
        let is_warm = state.sdb.check_account_in_access_list(&address);
        state.push_op_reversible(
            &mut exec_step,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        // Read account code hash and get code length.
        let account = state.sdb.get_account(&address).1;
        let exists = !account.is_empty();
        let code_hash = if exists {
            account.code_hash
        } else {
            H256::zero()
        };
        state.account_read(
            &mut exec_step,
            address,
            AccountField::CodeHash,
            code_hash.to_word(),
        );
        let code_size = if exists {
            state.code(code_hash)?.len()
        } else {
            0
        };

        // Write the EXTCODESIZE result to stack.
        debug_assert_eq!(code_size, geth_steps[1].stack.last()?.as_usize());
        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.nth_last_filled(0),
            code_size.into(),
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod extcodesize_tests {
    use super::{AccountField, CallContextField, TxAccessListAccountOp};
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{AccountOp, CallContextOp, StackOp, RW},
        state_db::CodeDB,
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::{Account, GethData},
        Bytecode, ToWord, U256,
    };
    #[cfg(feature = "kroma")]
    use mock::test_ctx::helpers::{setup_kroma_required_accounts, system_deposit_tx};
    use mock::{test_ctx::TestContext3_1, tx_idx, MOCK_1_ETH, MOCK_ACCOUNTS, MOCK_CODES};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_extcodesize_opcode() {
        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[4].clone(),
            ..Default::default()
        };

        // Test for empty account.
        test_ok(&Account::default(), false);
        // Test for cold account.
        test_ok(&account, false);
        // Test for warm account.
        test_ok(&account, true);
    }

    fn test_ok(account: &Account, is_warm: bool) {
        let exists = !account.is_empty();

        let mut bytecode = Bytecode::default();
        if is_warm {
            bytecode.append(&bytecode! {
                PUSH20(account.address.to_word())
                EXTCODESIZE
                POP
            });
        }
        bytecode.append(&bytecode! {
            PUSH20(account.address.to_word())
            EXTCODESIZE
            STOP
        });

        // Get the execution steps from the external tracer.
        let block: GethData = TestContext3_1::new(
            None,
            |mut accs| {
                accs[0]
                    .address(MOCK_ACCOUNTS[0])
                    .balance(*MOCK_1_ETH)
                    .code(bytecode);
                if exists {
                    accs[1].address(account.address).code(account.code.clone());
                } else {
                    accs[1].address(MOCK_ACCOUNTS[1]).balance(*MOCK_1_ETH);
                }
                accs[2].address(MOCK_ACCOUNTS[2]).balance(*MOCK_1_ETH);
                #[cfg(feature = "kroma")]
                setup_kroma_required_accounts(accs.as_mut_slice(), 3);
            },
            |mut txs, accs| {
                #[cfg(feature = "kroma")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        // Check if account address is in access list as a result of bus mapping.
        assert!(builder.sdb.add_account_to_access_list(account.address));

        let tx_id = tx_idx!(1);
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;

        let indices = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::EXTCODESIZE))
            .last()
            .unwrap()
            .bus_mapping_instance
            .clone();
        let container = builder.block.container;
        let operation = &container.stack[indices[0].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1023u32),
                value: account.address.to_word()
            }
        );

        let operation = &container.call_context[indices[1].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::TxId,
                value: tx_id.into()
            }
        );

        let operation = &container.call_context[indices[2].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::RwCounterEndOfReversion,
                value: U256::zero()
            }
        );

        let operation = &container.call_context[indices[3].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::IsPersistent,
                value: U256::one()
            }
        );

        let operation = &container.tx_access_list_account[indices[4].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &TxAccessListAccountOp {
                tx_id,
                address: account.address,
                is_warm: true,
                is_warm_prev: is_warm
            }
        );

        let code_hash = CodeDB::hash(&account.code).to_word();
        let operation = &container.account[indices[5].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &AccountOp {
                address: account.address,
                field: AccountField::CodeHash,
                value: if exists { code_hash } else { U256::zero() },
                value_prev: if exists { code_hash } else { U256::zero() },
            }
        );

        let operation = &container.stack[indices[6].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: 1023u32.into(),
                value: (if exists { account.code.len() } else { 0 }).into(),
            }
        );
    }
}
