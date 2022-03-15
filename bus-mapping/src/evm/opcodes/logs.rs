use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecState, ExecStep, StepAuxiliaryData};
use crate::operation::{CallContextField, CallContextOp, TxLogOp, TxLogField, RWCounter, RW};
use crate::Error;
use eth_types::{
    evm_types::{ProgramCounter, OpcodeId},
    GethExecStep, ToWord, Word,
};
use std::collections::HashMap;

// The max number of bytes that can be copied in a step limited by the number
// of cells in a step
const MAX_COPY_BYTES: usize = 71;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Log;

impl Opcode for Log {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        exec_step: &mut ExecStep,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];
        let mstart = step.stack.nth_last(0)?;
        let msize = step.stack.nth_last(1)?;
        
        let mut stack_index = 0;
        state.push_stack_op(
            exec_step,
            RW::READ,
            step.stack.nth_last_filled(stack_index),
            mstart,
        );
        state.push_stack_op(
            exec_step,
            RW::READ,
            step.stack.nth_last_filled(stack_index + 1),
            msize,
        );

        stack_index += 2 ;
        state.push_op(
            exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call().call_id,
                field: CallContextField::CalleeAddress,
                value: state.call().address.to_word(),
            },
        );
        // add tx log rw address
        state.push_op(
            exec_step,
            RW::WRITE,
            TxLogOp{
                 log_index: 0,
                 index: 0,
                 field_tag: TxLogField::Address,
                 value: state.call().address.to_word(),
            },
        );

        // topic in stack
        let topic_count = step.op.as_u8() - OpcodeId::LOG0.as_u8(); 
        for i in 0..topic_count {

            state.push_stack_op(
                exec_step,
                RW::READ,
                step.stack.nth_last_filled(stack_index),
                step.stack.nth_last(stack_index)?,
            );
        
            state.push_op(
                exec_step,
                RW::WRITE,
                TxLogOp{
                     log_index: 0,
                     index: i as usize,
                     field_tag: TxLogField::Topics,
                     value: step.stack.nth_last(stack_index)?,
                },
            );
            stack_index += 1;
        }

        // log data rws, this part should be multi step.
        // for i in 0..msize.try_into() {
        //     state.push_memory_op(exec_step, RW::READ, mem_read_addr, *value_byte);

        //     state.push_op(
        //         exec_step,
        //         RW::READ,
        //         Memor {
        //             call_id: state.call().call_id,
        //             field: CallContextField::IsStatic,
        //             value: state.call().is_static.into(),
        //         },
        //     );
        // }

        Ok(())
    }

    fn gen_associated_ops_multi(
        state: &mut CircuitInputStateRef,
        next_steps: &[GethExecStep],
    ) -> Result<(), Error> {
        // Generate an ExecStep of state Log.
        let mut copy_to_log_step = state.new_step(&next_steps[0]);
        Self::gen_associated_ops(state, &mut copy_to_log_step, next_steps)?;

        // Generate ExecSteps of virtual state CopyToLog.
        let copy_to_log_steps = gen_copy_to_log_steps(state, &copy_to_log_step, next_steps)?;

        state.push_step_to_tx(copy_to_log_step);
        for step in copy_to_log_steps {
            state.push_step_to_tx(step);
        }

        Ok(())
    }
}

fn gen_copy_to_log_step(
    state: &mut CircuitInputStateRef,
    last_step: &ExecStep,
    src_addr: u64,
    src_addr_end: u64,
    bytes_left: usize,
    memory_size: usize,
    log_index: u64,
    bytes_map: &HashMap<u64, u8>,
) -> ExecStep {
    let mut step = last_step.clone();
    step.rwc = RWCounter(step.rwc.0 + step.bus_mapping_instance.len());
    step.bus_mapping_instance = Vec::new();
    step.exec_state = ExecState::CopyToLog;
    step.pc = ProgramCounter(step.pc.0 + 1);
    step.stack_size = 0;
    step.memory_size = memory_size;

    let mut selectors = vec![0u8; MAX_COPY_BYTES];
    for (idx, selector) in selectors.iter_mut().enumerate() {
        if idx < bytes_left {
            *selector = 1;
            let addr = src_addr + idx as u64;
            let byte = if addr < src_addr_end {
                debug_assert!(bytes_map.contains_key(&addr));
                state.push_memory_op(
                    &mut step,
                    RW::READ,
                    (idx + src_addr as usize).into(),
                    bytes_map[&addr],
                );
                bytes_map[&addr]
            } else {
                0
            };

            state.push_log_op(&mut step, log_index, idx, TxLogField::Data, Word::from(byte));
        }
    }
    step.aux_data = Some(StepAuxiliaryData::CopyToLog {
        src_addr,
        bytes_left: bytes_left as u64,
        src_addr_end,
        selectors,
    });
    step
}

fn gen_copy_to_log_steps(
    state: &mut CircuitInputStateRef,
    copy_step: &ExecStep,
    next_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let memory_start = next_steps[0].stack.nth_last(0)?.as_u64();
    let msize = next_steps[0].stack.nth_last(2)?.as_usize();


    let (src_addr, buffer_addr, buffer_addr_end) = {
        (memory_start, memory_start + 0, memory_start + msize as u64)
    };

    let buffer: Vec<u8> = vec![0; (buffer_addr_end - buffer_addr) as usize];

    let memory_size = if msize == 0 {
        0
    } else {
        (memory_start + msize as u64 + 31) / 32 * 32
    };

    let bytes_map = (buffer_addr..buffer_addr_end)
        .zip(buffer.iter().copied())
        .collect();

    let mut copied = 0;
    let mut steps = vec![];
    let mut last_step = copy_step;

    while copied < msize {
        steps.push(gen_copy_to_log_step(
            state,
            last_step,
            memory_start,
            memory_start + msize as u64,
            msize,
            memory_size.try_into().unwrap(),
            0,
            &bytes_map,
        ));
        last_step = steps.last().unwrap();
        copied += MAX_COPY_BYTES;
    }

    Ok(steps)
}
