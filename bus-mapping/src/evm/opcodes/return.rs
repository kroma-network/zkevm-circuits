use super::Opcode;
// use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::{
    circuit_input_builder::CircuitInputStateRef,
    evm::opcodes::ExecStep,
    operation::{AccountField, CallContextField, TxAccessListAccountOp, RW},
    state_db::Account,
    Error,
};
use eth_types::{GethExecStep, ToWord};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::RETURN`](crate::evm::OpcodeId::RETURN).
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

        let offset = step.stack.last()?;
        state.stack_read(&mut exec_step, step.stack.last_filled(), offset)?;

        let length = step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(1), length)?;

        let call = *state.call()?;
        for (field, value) in [
            (CallContextField::IsRoot, call.is_root.to_word()),
            (CallContextField::IsCreate, call.is_create().to_word()),
            (CallContextField::IsSuccess, call.is_success.to_word()),
        ] {
            state.call_context_read(&mut exec_step, call.call_id, field, value);
        }

        // let result = state.handle_stop(steps);
        state.handle_return(step)?;
        Ok(vec![exec_step])
    }
}
