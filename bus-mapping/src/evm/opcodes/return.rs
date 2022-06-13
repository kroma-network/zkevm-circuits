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
        let current_call = state.call()?.clone();
        // copy return data
        let caller_ctx = &mut state.tx_ctx.calls[current_call.caller_id];
        if !current_call.is_create() {
            let geth_step = &geth_steps[0];
            let offset = geth_step.stack.nth_last(0)?.as_usize();
            let length = geth_step.stack.nth_last(1)?.as_usize();
            // update to the caller memory
            let return_offset = current_call.return_data_offset as usize;
            caller_ctx.memory.resize(return_offset + length, 0);
            caller_ctx.memory[return_offset..return_offset + length].copy_from_slice(&geth_steps[0].memory.0[offset..offset + length]);
            caller_ctx.return_data.resize(length as usize, 0);
            caller_ctx.return_data.copy_from_slice(&geth_steps[0].memory.0[offset..offset + length]);
            caller_ctx.last_call = Some(current_call.clone());
            assert_eq!(hex::encode(&caller_ctx.memory), hex::encode(&geth_steps[1].memory.0));
        }



        // let mut exec_steps = vec![gen_calldatacopy_step(state, geth_step)?];
        // let memory_copy_steps = gen_memory_copy_steps(state, geth_steps)?;
        // exec_steps.extend(memory_copy_steps);
        // Ok(exec_steps)
        let exec_step = state.new_step(&geth_steps[0])?;
        state.handle_return(&geth_steps[0])?;
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

#[cfg(test)]
mod return_tests {
    use eth_types::{bytecode, word};
    use eth_types::geth_types::GethData;
    use mock::TestContext;
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use crate::mock::BlockData;

    #[test]
    fn test_ok() {
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL
            STOP
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
    fn test_revert() {
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000FD600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL
            STOP
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