use eth_types::GethExecStep;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;
use crate::evm::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Returndatacopy;

impl Opcode for Returndatacopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep]
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let dest_offset = geth_step.stack.nth_last(0)?;
        let offset = geth_step.stack.nth_last(1)?;
        let size = geth_step.stack.nth_last(2)?;

        let call = state.call_ctx()?;
        let return_data = &call.return_data;

        let mut memory = geth_step.memory.0.clone();
        let length = size.as_usize();
        if length != 0 {
            let minimal_length = offset.as_usize() + length;
            if minimal_length > memory.len() {
                let resize = if minimal_length % 32 == 0 {
                    minimal_length
                } else {
                    (minimal_length / 32 + 1) * 32
                };
                memory.resize(resize, 0);
            }
            let mem_starts = dest_offset.as_usize();
            let mem_ends = mem_starts + length as usize;
            let data_starts = offset.as_usize();
            let data_ends = data_starts + size.as_usize();
            if data_ends < return_data.len() {
                memory[mem_starts..mem_ends].copy_from_slice(&return_data[data_starts..data_ends]);
            } else {
                let actual_length = return_data.len() - data_starts;
                let mem_data_ends = mem_starts + actual_length;
                memory[mem_starts..mem_data_ends].copy_from_slice(&return_data[data_starts..]);
                // since we already resize the memory, no need to copy 0s for out of bound bytes
            }
        }

        let exec_step = state.new_step(&geth_steps[0])?;
        Ok(vec![exec_step])

    }
}