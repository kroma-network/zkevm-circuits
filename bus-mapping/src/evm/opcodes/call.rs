use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{AccountField, CallContextField, TxAccessListAccountOp, RW},
    Error,
};
use eth_types::{
    evm_types::{
        gas_utils::{eip150_gas, memory_expansion_gas_cost},
        GasCost,
    },
    GethExecStep, ToWord,
};
use keccak256::EMPTY_HASH;
use log::warn;
use precompiled_adaptor::execute_precompiled;
use std::cmp::max;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::CALL` `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Call<const N_ARGS: usize>;

impl<const N_ARGS: usize> Opcode for Call<N_ARGS> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        assert!(N_ARGS == 6 || N_ARGS == 7);

        let geth_step = &geth_steps[0];

        let mut exec_step = state.new_step(geth_step)?;
        let tx_id = state.tx_ctx.id();
        let call = state.parse_call(geth_step)?;
        let current_call = state.call()?.clone();

        let args_offset = geth_step.stack.nth_last(N_ARGS - 4)?.as_usize();
        let args_length = geth_step.stack.nth_last(N_ARGS - 3)?.as_usize();
        let ret_offset = geth_step.stack.nth_last(N_ARGS - 2)?.as_usize();
        let ret_length = geth_step.stack.nth_last(N_ARGS - 1)?.as_usize();

        // we need to keep the memory until parse_call complete
        {
            let call_ctx = state.call_ctx_mut()?;
            let args_minimal = if args_length != 0 {
                args_offset + args_length
            } else {
                0
            };
            let ret_minimal = if ret_length != 0 {
                ret_offset + ret_length
            } else {
                0
            };
            if args_minimal != 0 || ret_minimal != 0 {
                let minimal_length = max(args_minimal, ret_minimal);
                call_ctx.memory.extend_at_least(minimal_length);
            }
        }

        // NOTE: For `RwCounterEndOfReversion` we use the `0` value as a placeholder,
        // and later set the proper value in
        // `CircuitInputBuilder::set_value_ops_call_context_rwc_eor`
        for (field, value) in [
            (CallContextField::TxId, tx_id.into()),
            (CallContextField::RwCounterEndOfReversion, 0.into()),
            (
                CallContextField::IsPersistent,
                (current_call.is_persistent as u64).into(),
            ),
            (
                CallContextField::CalleeAddress,
                current_call.address.to_word(),
            ),
            (
                CallContextField::IsStatic,
                (current_call.is_static as u64).into(),
            ),
            (CallContextField::Depth, current_call.depth.into()),
        ] {
            state.call_context_read(&mut exec_step, current_call.call_id, field, value);
        }

        for i in 0..N_ARGS {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        state.stack_write(
            &mut exec_step,
            geth_step.stack.nth_last_filled(N_ARGS - 1),
            (call.is_success as u64).into(),
        )?;

        let is_warm = state.sdb.check_account_in_access_list(&call.address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id,
                address: call.address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        // Switch to callee's call context
        state.push_call(call.clone());

        for (field, value) in [
            (CallContextField::RwCounterEndOfReversion, 0.into()),
            (
                CallContextField::IsPersistent,
                (call.is_persistent as u64).into(),
            ),
        ] {
            state.call_context_read(&mut exec_step, call.call_id, field, value);
        }

        state.transfer(
            &mut exec_step,
            call.caller_address,
            call.address,
            call.value,
        )?;

        let (_, callee_account) = state.sdb.get_account(&call.address);
        let is_account_empty = callee_account.is_empty();
        let callee_nonce = callee_account.nonce;
        let callee_code_hash = callee_account.code_hash;
        for (field, value) in [
            (AccountField::Nonce, callee_nonce),
            (AccountField::CodeHash, callee_code_hash.to_word()),
        ] {
            state.account_read(&mut exec_step, call.address, field, value, value)?;
        }

        // Calculate next_memory_word_size and callee_gas_left manually in case
        // there isn't next geth_step (e.g. callee doesn't have code).
        let next_memory_word_size = [
            state.call_ctx()?.memory.word_size() as u64,
            (call.call_data_offset + call.call_data_length + 31) / 32,
            (call.return_data_offset + call.return_data_length + 31) / 32,
        ]
        .into_iter()
        .max()
        .unwrap();
        let has_value = !call.value.is_zero();
        let gas_cost = if is_warm {
            GasCost::WARM_ACCESS.as_u64()
        } else {
            GasCost::COLD_ACCOUNT_ACCESS.as_u64()
        } + if has_value {
            GasCost::CALL_WITH_VALUE.as_u64()
                + if is_account_empty {
                    GasCost::NEW_ACCOUNT.as_u64()
                } else {
                    0
                }
        } else {
            0
        } + memory_expansion_gas_cost(
            state.caller_ctx()?.memory.word_size() as u64,
            next_memory_word_size,
        );
        let callee_gas_left = eip150_gas(geth_step.gas.0 - gas_cost, geth_step.stack.last()?);

        // There are 3 branches from here.
        let code_address = call.code_address();
        match (
            code_address
                .map(|ref addr| state.is_precompiled(addr))
                .unwrap_or(false),
            callee_code_hash.to_fixed_bytes() == *EMPTY_HASH,
        ) {
            // 1. Call to precompiled.
            (true, _) => {
                warn!("Call to precompiled is left unimplemented");

                // FIXME: is this correct?
                if call.is_success {
                    let caller_ctx = state.caller_ctx_mut()?;
                    let code_address = code_address.unwrap();
                    let result = execute_precompiled(
                        &code_address,
                        &caller_ctx.memory.0[args_offset..args_offset + args_length],
                    );
                    caller_ctx.memory.0[ret_offset..ret_offset + ret_length]
                        .copy_from_slice(&result[..ret_length]);
                }
                state.tx_ctx.pop_call_ctx();

                Ok(vec![exec_step])
            }
            // 2. Call to account with empty code.
            (_, true) => {
                for (field, value) in [
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                ] {
                    state.call_context_write(&mut exec_step, current_call.call_id, field, value);
                }
                state.handle_return(geth_step)?;
                Ok(vec![exec_step])
            }
            // 3. Call to account with non-empty code.
            (_, false) => {
                for (field, value) in [
                    (
                        CallContextField::ProgramCounter,
                        (geth_step.pc.0 + 1).into(),
                    ),
                    (
                        CallContextField::StackPointer,
                        (geth_step.stack.stack_pointer().0 + 6).into(),
                    ),
                    (
                        CallContextField::GasLeft,
                        (geth_step.gas.0 - gas_cost - callee_gas_left).into(),
                    ),
                    (CallContextField::MemorySize, next_memory_word_size.into()),
                    (
                        CallContextField::ReversibleWriteCounter,
                        (exec_step.reversible_write_counter + 1).into(),
                    ),
                ] {
                    state.call_context_write(&mut exec_step, current_call.call_id, field, value);
                }

                for (field, value) in [
                    (CallContextField::CallerId, current_call.call_id.into()),
                    (CallContextField::TxId, tx_id.into()),
                    (CallContextField::Depth, call.depth.into()),
                    (
                        CallContextField::CallerAddress,
                        call.caller_address.to_word(),
                    ),
                    (CallContextField::CalleeAddress, call.address.to_word()),
                    (
                        CallContextField::CallDataOffset,
                        call.call_data_offset.into(),
                    ),
                    (
                        CallContextField::CallDataLength,
                        call.call_data_length.into(),
                    ),
                    (
                        CallContextField::ReturnDataOffset,
                        call.return_data_offset.into(),
                    ),
                    (
                        CallContextField::ReturnDataLength,
                        call.return_data_length.into(),
                    ),
                    (CallContextField::Value, call.value),
                    (CallContextField::IsSuccess, (call.is_success as u64).into()),
                    (CallContextField::IsStatic, (call.is_static as u64).into()),
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                    (CallContextField::IsRoot, 0.into()),
                    (CallContextField::IsCreate, 0.into()),
                    (CallContextField::CodeHash, call.code_hash.to_word()),
                ] {
                    state.call_context_read(&mut exec_step, call.call_id, field, value);
                }

                Ok(vec![exec_step])
            }
        }
    }
}

#[cfg(test)]
mod call_tests {
    use crate::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    #[test]
    fn test_precompiled_call() {
        let code = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE

            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
            CALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_precompiled_callcode() {
        let code = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE

            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
            CALLCODE
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_precompiled_static_call() {
        let code = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE

            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_precompiled_delegate_call() {
        let code = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE

            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
            DELEGATECALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_ec_recover() {
        let code = bytecode! {
            // First place the parameters in memory
            PUSH32(word!("456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3")) // hash
            PUSH1(0)
            MSTORE
            PUSH1(28) // v
            PUSH1(0x20)
            MSTORE
            PUSH32(word!("9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608")) // r
            PUSH1(0x40)
            MSTORE
            PUSH32(word!("4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada")) // s
            PUSH1(0x60)
            MSTORE

            // Do the call
            PUSH1(32) // retSize
            PUSH1(0x80) // retOffset
            PUSH1(0x80) // argsSize
            PUSH1(0) // argsOffset
            PUSH1(1) // address
            PUSH4(word!("FFFFFFFF")) // gas
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_sha2() {
        let code = bytecode! {
            // First place the parameters in memory
            PUSH1(0xFF) // data
            PUSH1(0)
            MSTORE

            // Do the call
            PUSH1(0x20) // retSize
            PUSH1(0x20) // retOffset
            PUSH1(1) // argsSize
            PUSH1(0x1F) // argsOffset
            PUSH1(2) // address
            PUSH4(word!("FFFFFFFF")) // gas
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_ripemd_160() {
        let code = bytecode! {
            // First place the parameters in memory
            PUSH1(0xFF) // data
            PUSH1(0)
            MSTORE

            // Do the call
            PUSH1(0x20) // retSize
            PUSH1(0x20) // retOffset
            PUSH1(1) // argsSize
            PUSH1(0x1F) // argsOffset
            PUSH1(3) // address
            PUSH4(word!("FFFFFFFF")) // gas
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_modexp() {
        let code = bytecode! {
            // First place the parameters in memory
            PUSH1(1) // Bsize
            PUSH1(0)
            MSTORE
            PUSH1(1) // Esize
            PUSH1(0x20)
            MSTORE
            PUSH1(1) // Msize
            PUSH1(0x40)
            MSTORE
            PUSH32(word!("08090A0000000000000000000000000000000000000000000000000000000000")) // B, E and M
            PUSH1(0x60)
            MSTORE

            // Do the call
            PUSH1(1) // retSize
            PUSH1(0x9F) // retOffset
            PUSH1(0x63) // argsSize
            PUSH1(0) // argsOffset
            PUSH1(5) // address
            PUSH4(word!("FFFFFFFF")) // gas
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_ec_add() {
        let code = bytecode! {
            // First place the parameters in memory
            PUSH1(1) // x1
            PUSH1(0)
            MSTORE
            PUSH1(2) // y1
            PUSH1(0x20)
            MSTORE
            PUSH1(1) // x2
            PUSH1(0x40)
            MSTORE
            PUSH1(2) // y2
            PUSH1(0x60)
            MSTORE

            // Do the call
            PUSH1(0x40) // retSize
            PUSH1(0x80) // retOffset
            PUSH1(0x80) // argsSize
            PUSH1(0) // argsOffset
            PUSH1(6) // address
            PUSH4(word!("FFFFFFFF")) // gas
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_ec_mul() {
        let code = bytecode! {
            // First place the parameters in memory
            PUSH1(1) // x1
            PUSH1(0)
            MSTORE
            PUSH1(2) // y1
            PUSH1(0x20)
            MSTORE
            PUSH1(2) // s
            PUSH1(0x40)
            MSTORE

            // Do the call
            PUSH1(0x40) // retSize
            PUSH1(0x60) // retOffset
            PUSH1(0x60) // argsSize
            PUSH1(0) // argsOffset
            PUSH1(7) // address
            PUSH4(word!("FFFFFFFF")) // gas
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_ec_pairing() {
        let code = bytecode! {
            PUSH32(word!("2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
            PUSH1(0x0)
            MSTORE

            PUSH32(word!("2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
            PUSH1(0x20)
            MSTORE

            PUSH32(word!("1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
            PUSH1(0x40)
            MSTORE

            PUSH32(word!("22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
            PUSH1(0x60)
            MSTORE

            PUSH32(word!("2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
            PUSH1(0x80)
            MSTORE

            PUSH32(word!("2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
            PUSH1(0xA0)
            MSTORE

            PUSH32(word!("0000000000000000000000000000000000000000000000000000000000000001"))
            PUSH1(0xC0)
            MSTORE

            PUSH32(word!("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
            PUSH1(0xE0)
            MSTORE

            PUSH32(word!("1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
            PUSH2(0x0100)
            MSTORE

            PUSH32(word!("091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
            PUSH2(0x0120)
            MSTORE

            PUSH32(word!("2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
            PUSH2(0x0140)
            MSTORE

            PUSH32(word!("23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
            PUSH2(0x0160)
            MSTORE


            PUSH1(0x20) // retSize
            PUSH2(0x180)  // retOffset
            PUSH2(0x0180) // argsSize
            PUSH1(0x0) // argsOffset
            PUSH1(0x08) // address
            PUSH4(word!("FFFFFFFF")) // gas
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_blake2f() {
        let code = bytecode! {
            PUSH1(0x0000000C)
            PUSH1(0x0)
            MSTORE

            PUSH32(word!("48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"))
            PUSH1(0x20)
            MSTORE
            PUSH32(word!("d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"))
            PUSH1(0x40)
            MSTORE

            PUSH32(word!("6162630000000000000000000000000000000000000000000000000000000000"))
            PUSH1(0x60)
            MSTORE
            PUSH32(0x0)
            PUSH1(0xC0)
            MSTORE

            PUSH32(word!("0300000000000000010000000000000000000000000000000000000000000000"))
            PUSH1(0xE0)
            MSTORE

            // Do the call
            PUSH1(0x40) // retSize
            PUSH1(0xC0) // retOffset
            PUSH1(212) // argsSize
            PUSH1(28) // argsOffset
            PUSH1(0x04) // address
            PUSH4(word!("FFFFFFFF")) // gas
            STATICCALL
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }
}
