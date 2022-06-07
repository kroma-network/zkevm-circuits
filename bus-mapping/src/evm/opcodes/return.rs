use eth_types::GethExecStep;
use crate::circuit_input_builder::{CallKind, CircuitInputStateRef, ExecStep};
use crate::Error;
use crate::evm::Opcode;
use crate::operation::RW;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Return;


impl Opcode for Return {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep]
    ) -> Result<Vec<ExecStep>, Error> {
        let current_call = state.call()?;
        // copy return data
        let caller = &state.tx.calls()[current_call.caller_id];
        let caller_ctx = &mut state.tx_ctx.calls[current_call.caller_id];
        if current_call.is_success && !current_call.is_create() {
            let length = current_call.return_data_length;
            let offset = current_call.return_data_offset;

            // update to the caller memory
            debug_assert_eq!(caller.return_data_length, length);
            let return_offset = caller.return_data_offset;
            caller_ctx.memory[return_offset..return_offset + length].copy_from_slice(step.memory[offset..offset + length]);
        }


        // let mut exec_steps = vec![gen_calldatacopy_step(state, geth_step)?];
        // let memory_copy_steps = gen_memory_copy_steps(state, geth_steps)?;
        // exec_steps.extend(memory_copy_steps);
        // Ok(exec_steps)
        let exec_step = state.new_step(&geth_steps[0])?;
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }
}

// fn gen_calldatacopy_step(
//     state: &mut CircuitInputStateRef,
//     geth_step: &GethExecStep,
// ) -> Result<ExecStep, Error> {
//     let mut exec_step = state.new_step(geth_step)?;
//
//     let memory_offset = geth_step.stack.nth_last(0)?;
//     let memory_size = geth_step.stack.nth_last(1)?;
//
//     if cfg!(debug_assertions) {
//         let current_call = state.call()?;
//         debug_assert_eq!(memory_offset.as_u64(), current_call.return_data_offset);
//         debug_assert_eq!(memory_size.as_u64(), current_call.return_data_length);
//     }
//
//     state.push_stack_op(
//         &mut exec_step,
//         RW::READ,
//         geth_step.stack.nth_last_filled(0),
//         memory_offset,
//     )?;
//     state.push_stack_op(
//         &mut exec_step,
//         RW::READ,
//         geth_step.stack.nth_last_filled(1),
//         memory_size,
//     )?;
//
//     Ok(exec_step)
// }
//
// fn gen_memory_copy_steps(
//     state: &mut CircuitInputStateRef,
//     geth_steps: &[GethExecStep],
// ) -> Result<Vec<ExecStep>, Error> {
//
//     let memory_offset = geth_steps[0].stack.nth_last(0)?;
//     let memory_size = geth_steps[0].stack.nth_last(1)?;
//
//     if current_call.is_success && !current_call.is_create() {
//         let length = current_call.return_data_length;
//         let offset = current_call.return_data_offset;
//
//         // update to the caller memory
//         debug_assert_eq!(caller.return_data_length, length);
//         let return_offset = caller.return_data_offset;
//         caller_ctx.memory[return_offset..return_offset + length].copy_from_slice(step.memory[offset..offset + length]);
//     }
//
//     Ok(vec![])
// }