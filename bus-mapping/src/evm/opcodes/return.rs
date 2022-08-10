use super::Opcode;
use crate::circuit_input_builder::CopyEvent;
use crate::circuit_input_builder::CopyStep;
use crate::circuit_input_builder::{CopyDataType, NumberOrHash};
use crate::operation::MemoryOp;
use crate::{
    circuit_input_builder::CircuitInputStateRef,
    evm::opcodes::ExecStep,
    operation::{AccountField, CallContextField, TxAccessListAccountOp, RW},
    state_db::Account,
    Error,
};
use eth_types::{GethExecStep, ToWord};
use std::cmp::max;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Return;

// rename to ReturnRevertStop?
impl Opcode for Return {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let step = &steps[0];
        let mut exec_step = state.new_step(step)?;

        let offset = step.stack.nth_last(0)?;
        let length = step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(0), offset);
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(1), length);

        if !length.is_zero() {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least((offset.low_u64() + length.low_u64()).try_into().unwrap());
            // TODO: handle memory expansion gas cost!!
        }

        let call = state.call()?.clone();
        let is_root = call.is_root;
        for (field, value) in [
            (CallContextField::IsRoot, is_root.to_word()),
            (CallContextField::IsCreate, call.is_create().to_word()),
            (CallContextField::IsSuccess, call.is_success.to_word()), // done in handle stop
            (CallContextField::CallerId, call.caller_id.into()),
            (
                CallContextField::ReturnDataOffset,
                call.return_data_offset.into(),
            ),
            (
                CallContextField::ReturnDataLength,
                call.return_data_length.into(),
            ),
        ] {
            state.call_context_read(&mut exec_step, call.call_id, field, value);
        }

        // move this into handle_restore_context?
        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::IsSuccess,
            call.is_success.to_word(),
        );

        if !is_root {
            state.handle_restore_context(steps, &mut exec_step);
        }

        let memory = state.call_ctx()?.memory.clone();
        // dbg!(offset, length);
        let offset = offset.low_u64() as usize;
        let length = length.low_u64() as usize;
        if !is_root && call.is_create() {
            // this doesn't always need to be true.
            assert!(offset + length <= memory.0.len());
            let code = memory.0[offset..offset + length].to_vec();
            state.code_db.insert(code);
        } else if !is_root {
            let caller_ctx = state.caller_ctx_mut()?;
            let return_offset = call.return_data_offset as usize;

            let copy_len = std::cmp::min(call.return_data_length as usize, length);
            caller_ctx.memory.0[return_offset..return_offset + copy_len]
                .copy_from_slice(&memory.0[offset..offset + copy_len]);
            caller_ctx.return_data.resize(length as usize, 0);
            caller_ctx.return_data[0..copy_len]
                .copy_from_slice(&memory.0[offset..offset + copy_len]);

            if length > 0 {
                handle_copy(
                    state,
                    &mut exec_step,
                    Source {
                        tag: CopyDataType::Memory,
                        id: call.call_id,
                        offset: offset.try_into().unwrap(),
                        bytes: memory.0[offset..offset + length].to_vec(),
                    },
                    Destination {
                        tag: CopyDataType::Memory,
                        id: call.caller_id,
                        offset: call.return_data_offset,
                        length: call.return_data_length.try_into().unwrap(),
                    },
                );
            }
        }

        state.handle_return(step)?;
        Ok(vec![exec_step])
    }
}

struct Source {
    tag: CopyDataType,
    id: usize,
    offset: u64,
    bytes: Vec<u8>,
}

struct Destination {
    tag: CopyDataType,
    id: usize,
    offset: u64,
    length: usize,
}

fn handle_copy(
    state: &mut CircuitInputStateRef,
    step: &mut ExecStep,
    source: Source,
    destination: Destination,
) {
    let mut buffer: Vec<u8> = vec![];
    let mut rw_counters = vec![];
    for i in 0..destination.length {
        let read_rw_counter = state.block_ctx.rwc;
        let byte = match source.bytes.get(i + destination.offset as usize) {
            Some(byte) => {
                state.push_op(
                    step,
                    RW::READ,
                    MemoryOp::new(
                        source.id,
                        (source.offset + destination.offset + i as u64).into(),
                        *byte,
                    ),
                );
                *byte
            }
            None => 0,
        };
        // let read_rw_counter = state.block_ctx.rwc;
        let write_rw_counter = state.block_ctx.rwc;
        state.push_op(
            step,
            RW::WRITE,
            MemoryOp::new(destination.id, (destination.offset + i as u64).into(), byte),
        );
        // let write_rw_counter = state.block_ctx.rwc;

        rw_counters.push((read_rw_counter, write_rw_counter));

        buffer.push(byte);
    }

    dbg!(&rw_counters);

    let rw_counter_end = rw_counters.last().unwrap().1 .0;
    let mut copy_steps = vec![];
    for ((i, byte), &(read_rw_counter, write_rw_counter)) in
        buffer.iter().enumerate().zip(&rw_counters)
    {
        copy_steps.push(CopyStep {
            addr: source.offset + destination.offset as u64 + i as u64,
            tag: source.tag,
            rw: RW::READ,
            value: *byte,
            is_code: None,
            is_pad: false,
            rwc: read_rw_counter,
            rwc_inc_left: (rw_counter_end - read_rw_counter.0 + 1).try_into().unwrap(),
        });
        copy_steps.push(CopyStep {
            addr: destination.offset + i as u64,
            tag: destination.tag,
            rw: RW::WRITE,
            value: *byte,
            is_code: None,
            is_pad: false,
            rwc: write_rw_counter,
            rwc_inc_left: (rw_counter_end - write_rw_counter.0 + 1)
                .try_into()
                .unwrap(),
        });
        assert!(rw_counter_end - read_rw_counter.0 + 1 != 0);
        assert!(rw_counter_end - write_rw_counter.0 + 1 != 0);
    }

    assert_eq!(buffer.len(), destination.length);
    assert_eq!(2 * buffer.len(), copy_steps.len());

    // dbg!(source.id, destination.id);
    let src_addr_end = source.offset + u64::try_from(source.bytes.len()).unwrap();
    // dbg!(src_addr_end);

    state.push_copy(CopyEvent {
        src_type: CopyDataType::Memory,
        src_id: NumberOrHash::Number(source.id),
        src_addr: 0, // not used
        src_addr_end,
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(destination.id),
        dst_addr: 0, // not used....
        length: buffer.len().try_into().unwrap(),
        log_id: None,
        steps: copy_steps,
    });
}
