use super::Opcode;
// use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::{
    circuit_input_builder::CircuitInputStateRef, evm::opcodes::ExecStep,
    operation::CallContextField, Error,
};
use eth_types::{GethExecStep, ToWord};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::RETURN`](crate::evm::OpcodeId::RETURN).
#[derive(Debug, Copy, Clone)]
pub(crate) struct Return;

// TODO: this also handles Revert, so a better name may be Halt? It could also
// handle Stop?
impl Opcode for Return {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let step = &steps[0];
        let mut exec_step = state.new_step(step)?;

        let offset = step.stack.last()?;
        state.stack_read(&mut exec_step, step.stack.last_filled(), offset)?;

        let length = step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(1), length)?;

        let call = state.call()?.clone();
        for (field, value) in [
            (CallContextField::IsRoot, call.is_root.to_word()),
            (CallContextField::IsCreate, call.is_create().to_word()),
            (CallContextField::IsSuccess, call.is_success.to_word()), // done in handle stop
        ] {
            state.call_context_read(&mut exec_step, call.call_id, field, value);
        }

        if !call.is_root {
            let caller = state.caller()?.clone();
            state.call_context_read(
                &mut exec_step,
                call.call_id,
                CallContextField::CallerId,
                caller.call_id.into(),
            );

            let geth_step_next = &steps[1];
            let caller_gas_left = geth_step_next.gas.0 - step.gas.0;
            for (field, value) in [
                (CallContextField::IsRoot, (caller.is_root as u64).into()),
                (
                    CallContextField::IsCreate,
                    (caller.is_create() as u64).into(),
                ),
                (CallContextField::CodeHash, caller.code_hash.to_word()),
                (CallContextField::ProgramCounter, geth_step_next.pc.0.into()),
                (
                    CallContextField::StackPointer,
                    geth_step_next.stack.stack_pointer().0.into(),
                ),
                (CallContextField::GasLeft, caller_gas_left.into()),
                (
                    CallContextField::MemorySize,
                    geth_step_next.memory.word_size().into(),
                ),
                (
                    CallContextField::ReversibleWriteCounter,
                    state.caller_ctx()?.reversible_write_counter.into(),
                ),
            ] {
                state.call_context_read(&mut exec_step, caller.call_id, field, value);
            }

            for (field, value) in [
                (CallContextField::LastCalleeId, call.call_id.into()),
                (CallContextField::LastCalleeReturnDataOffset, offset),
                (CallContextField::LastCalleeReturnDataLength, length),
            ] {
                state.call_context_write(&mut exec_step, caller.call_id, field, value);
            }

            state.call_context_read(
                &mut exec_step,
                call.call_id,
                CallContextField::IsSuccess,
                call.is_success.to_word(),
            );
        }

        state.handle_return(step)?;
        Ok(vec![exec_step])
    }
}
