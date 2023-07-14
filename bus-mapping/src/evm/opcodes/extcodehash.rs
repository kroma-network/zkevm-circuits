use super::Opcode;
use crate::{
    circuit_input_builder::CircuitInputStateRef,
    evm::opcodes::ExecStep,
    operation::{AccountField, CallContextField, TxAccessListAccountOp},
    Error,
};
use eth_types::{GethExecStep, ToAddress, ToWord, H256, U256};

#[derive(Debug, Copy, Clone)]
pub(crate) struct Extcodehash;

impl Opcode for Extcodehash {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let step = &steps[0];
        let mut exec_step = state.new_step(step)?;
        let stack_address = step.stack.last_filled();

        // Pop external address off stack
        let external_address_word = step.stack.last()?;
        let external_address = external_address_word.to_address();
        state.stack_read(&mut exec_step, stack_address, external_address_word)?;

        // Read transaction id, rw_counter_end_of_reversion, and is_persistent from call
        // context

        for (field, value) in [
            (CallContextField::TxId, U256::from(state.tx_ctx.id())),
            (
                CallContextField::RwCounterEndOfReversion,
                U256::from(state.call()?.rw_counter_end_of_reversion as u64),
            ),
            (
                CallContextField::IsPersistent,
                U256::from(state.call()?.is_persistent as u64),
            ),
        ] {
            state.call_context_read(&mut exec_step, state.call()?.call_id, field, value);
        }

        // Update transaction access list for external_address
        let is_warm = state.sdb.check_account_in_access_list(&external_address);
        state.push_op_reversible(
            &mut exec_step,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address: external_address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        let account = state.sdb.get_account(&external_address).1;
        let exists = !account.is_empty();
        let code_hash = if exists {
            account.code_hash
        } else {
            H256::zero()
        };
        // log::trace!("extcodehash addr {:?} acc {:?} exists {:?} codehash {:?}",
        // external_address, account, exists, code_hash);
        state.account_read(
            &mut exec_step,
            external_address,
            AccountField::CodeHash,
            code_hash.to_word(),
        );
        debug_assert_eq!(steps[1].stack.last()?, code_hash.to_word());
        // Stack write of the result of EXTCODEHASH.
        state.stack_write(&mut exec_step, stack_address, steps[1].stack.last()?)?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod extcodehash_tests {
    use super::Error;
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
        Bytecode, Bytes, ToWord, Word, U256,
    };
    #[cfg(feature = "kroma")]
    use mock::test_ctx::helpers::{setup_kroma_required_accounts, system_deposit_tx};
    use mock::{test_ctx::TestContext3_1, tx_idx};
    use pretty_assertions::assert_eq;

    #[test]
    fn cold_empty_account() -> Result<(), Error> {
        test_ok(false, false)
    }

    #[test]
    fn warm_empty_account() -> Result<(), Error> {
        test_ok(false, true)
    }

    #[test]
    fn cold_existing_account() -> Result<(), Error> {
        test_ok(true, false)
    }

    #[test]
    fn warm_existing_account() -> Result<(), Error> {
        test_ok(true, true)
    }

    fn test_ok(exists: bool, is_warm: bool) -> Result<(), Error> {
        // In each test case, this is the external address we will call EXTCODEHASH on.
        let external_address = address!("0xaabbccddee000000000000000000000000000000");

        // Make the external account warm, if needed, by first getting its balance.
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                PUSH20(external_address.to_word())
                EXTCODEHASH
                POP
            });
        }
        code.append(&bytecode! {
            PUSH20(external_address.to_word())
            EXTCODEHASH
            STOP
        });
        let mut nonce = 300u64;
        let mut balance = Word::from(800u64);
        let mut code_ext = Bytes::from([34, 54, 56]);

        if !exists {
            nonce = 0;
            balance = Word::zero();
            code_ext = Bytes::default();
        }

        // Get the execution steps from the external tracer
        let block: GethData = TestContext3_1::new(
            None,
            |mut accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(code.clone());

                accs[1]
                    .address(external_address)
                    .balance(balance)
                    .nonce(nonce)
                    .code(code_ext.clone());

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

        let code_hash = CodeDB::hash(&code_ext).to_word();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        // Check that `external_address` is in access list as a result of bus mapping.
        assert!(builder.sdb.add_account_to_access_list(external_address));

        let tx_id = tx_idx!(1);
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;

        let indices = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::EXTCODEHASH))
            .last()
            .unwrap()
            .bus_mapping_instance
            .clone();
        let container = builder.block.container;
        assert_eq!(
            {
                let operation = &container.stack[indices[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &StackOp {
                    call_id,
                    address: StackAddress::from(1023u32),
                    value: external_address.to_word()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[1].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::TxId,
                    value: tx_id.into()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[2].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::RwCounterEndOfReversion,
                    value: U256::zero()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[3].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::IsPersistent,
                    value: U256::one()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.tx_access_list_account[indices[4].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &TxAccessListAccountOp {
                    tx_id,
                    address: external_address,
                    is_warm: true,
                    is_warm_prev: is_warm
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.account[indices[5].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &AccountOp {
                    address: external_address,
                    field: AccountField::CodeHash,
                    value: if exists { code_hash } else { U256::zero() },
                    value_prev: if exists { code_hash } else { U256::zero() },
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.stack[indices[6].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &StackOp {
                    call_id,
                    address: 1023u32.into(),
                    value: if exists { code_hash } else { U256::zero() }
                }
            )
        );

        Ok(())
    }
}
