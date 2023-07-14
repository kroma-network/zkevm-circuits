use super::Opcode;
use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    operation::CallContextField,
    Error,
};
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Calldatacopy;

impl Opcode for Calldatacopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_calldatacopy_step(state, geth_step)?];

        // reconstruction
        let memory_offset = geth_step.stack.nth_last(0)?;
        let data_offset = geth_step.stack.nth_last(1)?;
        let length = geth_step.stack.nth_last(2)?;
        let call_ctx = state.call_ctx_mut()?;
        let memory = &mut call_ctx.memory;

        memory.copy_from(memory_offset, data_offset, length, &call_ctx.call_data);

        let copy_event = gen_copy_event(state, geth_step)?;
        state.push_copy(&mut exec_steps[0], copy_event);
        Ok(exec_steps)
    }
}

fn gen_calldatacopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;
    let memory_offset = geth_step.stack.nth_last(0)?;
    let data_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?;

    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(0),
        memory_offset,
    )?;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(1),
        data_offset,
    )?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), length)?;

    if state.call()?.is_root {
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            state.tx_ctx.id().into(),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CallDataLength,
            state.call()?.call_data_length.into(),
        );
    } else {
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CallerId,
            state.call()?.caller_id.into(),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CallDataLength,
            state.call()?.call_data_length.into(),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CallDataOffset,
            state.call()?.call_data_offset.into(),
        );
    };

    Ok(exec_step)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<CopyEvent, Error> {
    let rw_counter_start = state.block_ctx.rwc;

    let memory_offset = geth_step.stack.nth_last(0)?;
    let data_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?.as_u64();

    let call_data_offset = state.call()?.call_data_offset;
    let call_data_length = state.call()?.call_data_length;

    // Get low Uint64 of offset.
    let dst_addr = memory_offset.low_u64();
    let src_addr_end = call_data_offset.checked_add(call_data_length).unwrap();

    // Reset offset to call_data_length if overflow, and set source start to the
    // minimum value of offset and call_data_length.
    let src_addr = u64::try_from(data_offset)
        .ok()
        .and_then(|offset| offset.checked_add(call_data_offset))
        .unwrap_or(src_addr_end)
        .min(src_addr_end);

    let mut exec_step = state.new_step(geth_step)?;
    let copy_steps = state.gen_copy_steps_for_call_data(
        &mut exec_step,
        src_addr,
        dst_addr,
        src_addr_end,
        length,
    )?;

    let (src_type, src_id) = if state.call()?.is_root {
        (CopyDataType::TxCalldata, state.tx_ctx.id())
    } else {
        (CopyDataType::Memory, state.call()?.caller_id)
    };

    Ok(CopyEvent {
        src_type,
        src_id: NumberOrHash::Number(src_id),
        src_addr,
        src_addr_end,
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(state.call()?.call_id),
        dst_addr,
        log_id: None,
        rw_counter_start,
        bytes: copy_steps,
    })
}

#[cfg(test)]
mod calldatacopy_tests {
    use crate::{
        circuit_input_builder::{ExecState, NumberOrHash},
        mock::BlockData,
        operation::{CallContextField, CallContextOp, MemoryOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        ToWord, Word,
    };

    use mock::{
        test_ctx::{
            helpers::{
                account_0_code_account_1_no_code, setup_kroma_required_accounts, system_deposit_tx,
            },
            SimpleTestContext, TestContext3_1,
        },
        tx_idx,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn calldatacopy_opcode_internal() {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let dst_offset = 0x00usize;
        let offset = 0x00usize;
        let copy_size = 0x10usize;
        let code_b = bytecode! {
            PUSH32(copy_size)  // size
            PUSH32(offset)     // offset
            PUSH32(dst_offset) // dst_offset
            CALLDATACOPY
            STOP
        };

        // code A calls code B.
        let pushdata = hex::decode("1234567890abcdef").unwrap();
        let memory_a = std::iter::repeat(0)
            .take(24)
            .chain(pushdata.clone())
            .collect::<Vec<u8>>();
        let call_data_length = 0x20usize;
        let call_data_offset = 0x10usize;
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call addr_b.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH1(call_data_length) // argsLength
            PUSH1(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext3_1::new(
            None,
            |mut accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
                #[cfg(feature = "kroma")]
                setup_kroma_required_accounts(accs.as_mut_slice(), 3);
            },
            |mut txs, accs| {
                #[cfg(feature = "kroma")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[tx_idx!(0)]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLDATACOPY))
            .unwrap();

        let caller_id = builder.block.txs()[tx_idx!(0)].calls()[step.call_index].caller_id;
        let expected_call_id = builder.block.txs()[tx_idx!(0)].calls()[step.call_index].call_id;

        // 3 stack reads + 3 call context reads.
        assert_eq!(step.bus_mapping_instance.len(), 6);

        // 3 stack reads.
        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1021), Word::from(dst_offset))
                ),
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1022), Word::from(offset))
                ),
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1023), Word::from(copy_size))
                ),
            ]
        );

        // 3 call context reads.
        assert_eq!(
            [3, 4, 5]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: expected_call_id,
                        field: CallContextField::CallerId,
                        value: Word::from(caller_id),
                    }
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: expected_call_id,
                        field: CallContextField::CallDataLength,
                        value: Word::from(call_data_length),
                    },
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: expected_call_id,
                        field: CallContextField::CallDataOffset,
                        value: Word::from(call_data_offset),
                    },
                ),
            ]
        );

        // Memory reads/writes.
        //
        // 1. First `call_data_length` memory ops are RW::WRITE and come from the `CALL`
        // opcode. We skip checking those.
        //
        // 2. Following that, we should have tuples of (RW::READ and RW::WRITE) where
        // the caller memory is read and the current call's memory is written to.
        let memory_offset = builder
            .block
            .container
            .memory
            .iter()
            .position(|x| x.op().call_id == caller_id)
            .unwrap();
        assert_eq!(
            builder.block.container.memory.len() - memory_offset,
            call_data_length + 2 * copy_size
        );
        assert_eq!(
            (call_data_length..(call_data_length + (2 * copy_size)))
                .map(|idx| &builder.block.container.memory[memory_offset + idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            {
                let mut memory_ops = Vec::with_capacity(2 * copy_size);
                (0..copy_size).for_each(|idx| {
                    let value = if offset + call_data_offset + idx < memory_a.len() {
                        memory_a[offset + call_data_offset + idx]
                    } else {
                        0
                    };
                    memory_ops.push((
                        RW::READ,
                        MemoryOp::new(caller_id, (call_data_offset + offset + idx).into(), value),
                    ));
                    memory_ops.push((
                        RW::WRITE,
                        MemoryOp::new(expected_call_id, (dst_offset + idx).into(), value),
                    ));
                });
                memory_ops
            },
        );

        let copy_events = builder.block.copy_events.clone();
        assert_eq!(copy_events.len(), 1);
        assert_eq!(copy_events[0].bytes.len(), copy_size);
        assert_eq!(copy_events[0].src_id, NumberOrHash::Number(caller_id));
        assert_eq!(
            copy_events[0].dst_id,
            NumberOrHash::Number(expected_call_id)
        );
        assert!(copy_events[0].log_id.is_none());
        assert_eq!(copy_events[0].src_addr as usize, offset + call_data_offset);
        assert_eq!(
            copy_events[0].src_addr_end as usize,
            offset + call_data_offset + call_data_length
        );
        assert_eq!(copy_events[0].dst_addr as usize, dst_offset);

        for (idx, (value, is_code)) in copy_events[0].bytes.iter().enumerate() {
            assert_eq!(Some(value), memory_a.get(offset + call_data_offset + idx));
            assert!(!is_code);
        }
    }

    #[test]
    fn calldatacopy_opcode_internal_overflow() {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let dst_offset = 0x00usize;
        let offset = 0x00usize;
        let copy_size = 0x50usize;
        let code_b = bytecode! {
            PUSH32(copy_size)  // size
            PUSH32(offset)     // offset
            PUSH32(dst_offset) // dst_offset
            CALLDATACOPY
            STOP
        };

        // code A calls code B.
        let pushdata = hex::decode("1234567890abcdef").unwrap();
        let _memory_a = std::iter::repeat(0)
            .take(24)
            .chain(pushdata.clone())
            .collect::<Vec<u8>>();
        let call_data_length = 0x20usize;
        let call_data_offset = 0x10usize;
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call addr_b.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH1(call_data_length) // argsLength
            PUSH1(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext3_1::new(
            None,
            |mut accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
                #[cfg(feature = "kroma")]
                setup_kroma_required_accounts(accs.as_mut_slice(), 3);
            },
            |mut txs, accs| {
                #[cfg(feature = "kroma")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn calldatacopy_opcode_root() {
        let size = 0x40;
        let offset = 0x00;
        let dst_offset = 0x00;
        let calldata = vec![1, 3, 5, 7, 9, 2, 4, 6, 8];
        let calldata_len = calldata.len();
        let code = bytecode! {
            PUSH32(size)
            PUSH32(offset)
            PUSH32(dst_offset)
            CALLDATACOPY
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = SimpleTestContext::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                #[cfg(feature = "kroma")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .input(calldata.clone().into());
            },
            |block, _tx| block,
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[tx_idx!(0)]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLDATACOPY))
            .unwrap();

        let expected_call_id = builder.block.txs()[tx_idx!(0)].calls()[step.call_index].call_id;
        assert_eq!(step.bus_mapping_instance.len(), 5);

        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1021), dst_offset.into())
                ),
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1022), offset.into())
                ),
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1023), size.into())
                ),
            ]
        );

        assert_eq!(
            [3, 4]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: builder.block.txs()[tx_idx!(0)].calls()[0].call_id,
                        field: CallContextField::TxId,
                        value: Word::from(tx_idx!(1)),
                    }
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: builder.block.txs()[tx_idx!(0)].calls()[0].call_id,
                        field: CallContextField::CallDataLength,
                        value: calldata_len.into(),
                    },
                ),
            ]
        );

        // Memory reads/writes.
        //
        // 1. Since its a root call, we should only have memory RW::WRITE where the
        // current call's memory is written to.
        let memory_offset = builder
            .block
            .container
            .memory
            .iter()
            .position(|x| x.op().call_id == expected_call_id)
            .unwrap();
        assert_eq!(builder.block.container.memory.len() - memory_offset, size);
        assert_eq!(
            (0..size)
                .map(|idx| &builder.block.container.memory[memory_offset + idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            {
                let mut memory_ops = Vec::with_capacity(size);
                (0..size).for_each(|idx| {
                    let value = if offset + idx < calldata_len {
                        calldata[offset + idx]
                    } else {
                        0
                    };
                    memory_ops.push((
                        RW::WRITE,
                        MemoryOp::new(expected_call_id, (dst_offset + idx).into(), value),
                    ));
                });
                memory_ops
            },
        );

        let copy_events = builder.block.copy_events.clone();

        // single copy event with `size` reads and `size` writes.
        assert_eq!(copy_events.len(), 1);
        assert_eq!(copy_events[0].bytes.len(), size);

        for (idx, (value, is_code)) in copy_events[0].bytes.iter().enumerate() {
            assert_eq!(value, calldata.get(offset + idx).unwrap_or(&0));
            assert!(!is_code);
        }
    }
}
