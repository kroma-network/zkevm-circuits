use super::Opcode;
use crate::circuit_input_builder::{
    CircuitInputStateRef, CopyDetails, ExecState, ExecStep, StepAuxiliaryData,
};
use crate::constants::MAX_COPY_BYTES;
use crate::Error;
use eth_types::{GethExecStep, ToAddress, ToWord};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Extcodecopy;

impl Opcode for Extcodecopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_codecopy_step(state, geth_step)?];
        let memory_copy_steps = gen_memory_copy_steps(state, geth_steps)?;
        exec_steps.extend(memory_copy_steps);
        Ok(exec_steps)
    }
}

fn gen_codecopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;

    let address = geth_step.stack.nth_last(0)?;
    let dest_offset = geth_step.stack.nth_last(1)?;
    let offset = geth_step.stack.nth_last(2)?;
    let length = geth_step.stack.nth_last(3)?;

    // stack reads
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), address)?;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(1),
        dest_offset,
    )?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), offset)?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(3), length)?;
    Ok(exec_step)
}

/// FIXME: REFACTOR THIS
fn gen_memory_copy_step(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    aux_data: StepAuxiliaryData,
    code: &[u8],
) -> Result<(), Error> {
    for idx in 0..std::cmp::min(aux_data.bytes_left as usize, MAX_COPY_BYTES) {
        let addr = (aux_data.src_addr as usize) + idx;
        let byte = if addr < (aux_data.src_addr_end as usize) {
            code[addr]
        } else {
            0
        };
        state.memory_write(exec_step, ((aux_data.dst_addr as usize) + idx).into(), byte)?;
    }

    exec_step.aux_data = Some(aux_data);

    Ok(())
}

fn gen_memory_copy_steps(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let address = geth_steps[0].stack.nth_last(0)?.to_address();
    let dest_offset = geth_steps[0].stack.nth_last(1)?.as_u64();
    let code_offset = geth_steps[0].stack.nth_last(2)?.as_u64();
    let length = geth_steps[0].stack.nth_last(3)?.as_u64();

    let code_hash = state.code_hash(address)?;
    let code = state.code(code_hash)?;
    let src_addr_end = code.len() as u64;

    // TODO: COMPLETE MEMORY RECONSTRUCTION
    let mut memory = geth_steps[0].memory.0.clone();
    if length != 0 {
        let minimal_length = (dest_offset + length) as usize;
        if minimal_length > memory.len() {
            let resize = if minimal_length % 32 == 0 {
                minimal_length
            } else {
                (minimal_length / 32 + 1) * 32
            };
            memory.resize(resize, 0);
        }

        let mem_starts = dest_offset as usize;
        let mem_ends = mem_starts + length as usize;
        let code_starts = code_offset as usize;
        let code_ends = code_starts + length as usize;
        if code_ends <= code.len() {
            memory[mem_starts..mem_ends].copy_from_slice(&code[code_starts..code_ends]);
        } else {
            let actual_length = code.len() - code_starts;
            let mem_code_ends = mem_starts + actual_length;
            memory[mem_starts..mem_code_ends].copy_from_slice(&code[code_starts..]);
            // since we already resize the memory, no need to copy 0s for out of
            // bound bytes
        }
    }

    assert_eq!(memory, geth_steps[1].memory.0);
    state.call_ctx_mut()?.memory = memory;

    let code_source = code_hash.to_word();
    let mut copied = 0;
    let mut steps = vec![];
    while copied < length {
        let mut exec_step = state.new_step(&geth_steps[1])?;
        exec_step.exec_state = ExecState::CopyCodeToMemory;
        gen_memory_copy_step(
            state,
            &mut exec_step,
            StepAuxiliaryData::new(
                code_offset + copied,
                dest_offset + copied,
                length - copied,
                src_addr_end,
                CopyDetails::Code(code_source),
            ),
            &code,
        )?;
        steps.push(exec_step);
        copied += MAX_COPY_BYTES as u64;
    }

    Ok(steps)
}
