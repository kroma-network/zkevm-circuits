use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    evm::Opcode,
    operation::{AccountField, CallContextField, TxAccessListAccountOp},
    Error,
};
use eth_types::{GethExecStep, ToAddress, ToWord, H256, U256};

#[derive(Debug, Copy, Clone)]
pub(crate) struct Balance;

impl Opcode for Balance {
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

        // Read transaction ID, rw_counter_end_of_reversion, and is_persistent
        // from call context.
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            U256::from(state.tx_ctx.id()),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::RwCounterEndOfReversion,
            U256::from(state.call()?.rw_counter_end_of_reversion as u64),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::IsPersistent,
            U256::from(state.call()?.is_persistent as u64),
        );

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

        // Read account balance.
        let account = state.sdb.get_account(&address).1;
        let exists = !account.is_empty();
        let balance = account.balance;
        let code_hash = if exists {
            account.code_hash
        } else {
            H256::zero()
        };
        debug_assert_eq!(balance, geth_steps[1].stack.nth_last(0)?);
        state.account_read(
            &mut exec_step,
            address,
            AccountField::CodeHash,
            code_hash.to_word(),
        );
        if exists {
            state.account_read(&mut exec_step, address, AccountField::Balance, balance);
        }

        // Write the BALANCE result to stack.
        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.nth_last_filled(0),
            geth_steps[1].stack.nth_last(0)?,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod balance_tests {
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{
            AccountField, AccountOp, CallContextField, CallContextOp, StackOp,
            TxAccessListAccountOp, RW,
        },
        state_db::CodeDB,
    };
    use eth_types::{
        address, bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        Bytecode, ToWord, Word, U256,
    };
    #[cfg(feature = "kroma")]
    use mock::test_ctx::helpers::{setup_kroma_required_accounts, system_deposit_tx};
    use mock::{test_ctx::TestContext3_1, tx_idx};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_balance_of_non_existing_address() {
        test_ok(false, false, None);
    }

    #[test]
    fn test_balance_of_cold_address() {
        test_ok(true, false, None);
        test_ok(true, false, Some(vec![1, 2, 3]))
    }

    #[test]
    fn test_balance_of_warm_address() {
        test_ok(true, true, None);
        test_ok(true, true, Some(vec![2, 3, 4]))
    }

    // account_code = None should be the same as exists = false, so we can remove
    // it.
    fn test_ok(exists: bool, is_warm: bool, account_code: Option<Vec<u8>>) {
        let address = address!("0xaabbccddee000000000000000000000000000000");

        // Pop balance first for warm account.
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                PUSH20(address.to_word())
                BALANCE
                POP
            });
        }
        code.append(&bytecode! {
            PUSH20(address.to_word())
            BALANCE
            STOP
        });

        let balance = if exists {
            Word::from(800u64)
        } else {
            Word::zero()
        };

        // Get the execution steps from the external tracer.
        let block: GethData = TestContext3_1::new(
            None,
            |mut accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(code.clone());
                if exists {
                    if let Some(code) = account_code.clone() {
                        accs[1].address(address).balance(balance).code(code);
                    } else {
                        accs[1].address(address).balance(balance);
                    }
                } else {
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000020"))
                        .balance(Word::from(1u64 << 20));
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000cafe01"))
                    .balance(Word::from(1u64 << 20));
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
        assert!(builder.sdb.add_account_to_access_list(address));

        let tx_id = tx_idx!(1);
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;

        let indices = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::BALANCE))
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
                value: address.to_word()
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
                address,
                is_warm: true,
                is_warm_prev: is_warm
            }
        );

        let code_hash = if let Some(code) = account_code {
            CodeDB::hash(&code).to_word()
        } else if exists {
            CodeDB::empty_code_hash().to_word()
        } else {
            U256::zero()
        };
        let operation = &container.account[indices[5].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &AccountOp {
                address,
                field: AccountField::CodeHash,
                value: if exists { code_hash } else { U256::zero() },
                value_prev: if exists { code_hash } else { U256::zero() },
            }
        );
        if exists {
            let operation = &container.account[indices[6].as_usize()];
            assert_eq!(operation.rw(), RW::READ);
            assert_eq!(
                operation.op(),
                &AccountOp {
                    address,
                    field: AccountField::Balance,
                    value: balance,
                    value_prev: balance,
                }
            );
        }

        let operation = &container.stack[indices[6 + if exists { 1 } else { 0 }].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: 1023u32.into(),
                value: balance,
            }
        );
    }
}
