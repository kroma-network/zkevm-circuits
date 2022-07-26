use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::error::ExecError;
use crate::evm::{Opcode, OpcodeId};
use crate::Error;
use eth_types::{GethExecStep, ToAddress, ToWord, Word};

#[derive(Debug, Copy, Clone)]
pub(crate) struct ErrorDepth;

impl Opcode for ErrorDepth {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        // there's no way to have ErrorDepth in the last step
        assert!(geth_steps.len() > 1);
        let geth_step = &geth_steps[0];
        let next_step = &geth_steps[1];
        // sanity check
        assert!(geth_step.op.is_call());
        assert_eq!(geth_step.depth, 1025);
        let minimal_stack_elements = match geth_step.op {
            OpcodeId::CALL | OpcodeId::CALLCODE => 7,
            OpcodeId::STATICCALL | OpcodeId::DELEGATECALL => 6,
            _ => unreachable!(),
        };
        assert!(geth_step.stack.0.len() >= minimal_stack_elements);

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::Depth);

        // we don't need to parse the call, only need the word value here
        for offset in 0..minimal_stack_elements {
            let value = geth_step.stack.nth_last(offset)?;
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(offset),
                value,
            )?;
        }

        // the call attempt must fail immediately (sub context reverts)
        // but won't revert current context
        assert_eq!(next_step.stack.nth_last(0)?, Word::zero());
        state.stack_write(
            &mut exec_step,
            next_step.stack.nth_last_filled(0),
            Word::zero(),
        )?;
        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod error_depth_tests {
    use crate::circuit_input_builder::CircuitsParams;
    use crate::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::account_0_code_account_1_no_code;
    use mock::TestContext;

    #[test]
    fn test_depth() {
        let code = bytecode! {
            PUSH32(word!("0x7f602060006000376000600060206000600060003561ffff5a03f10000000000"))
            PUSH1(0x0)
            MSTORE
            PUSH32(word!("0x0060005260206000F30000000000000000000000000000000000000000000000"))
            PUSH1(0x20)
            MSTORE

            PUSH1(0x40)
            PUSH1(0x0)
            PUSH1(0x0)
            CREATE

            DUP1
            PUSH1(0x40)
            MSTORE

            PUSH1(0x0) // retSize
            PUSH1(0x0) // retOffset
            PUSH1(0x20) // argSize
            PUSH1(0x40) // argOffset
            PUSH1(0x0) // Value
            DUP6
            PUSH2(0xFF)
            GAS
            SUB
            CALL
        };
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .gas(word!("0x2386F26FC10000"));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        let mut builder = BlockData::new_from_geth_data_with_params(
            block.clone(),
            CircuitsParams {
                max_rws: 200000,
                ..Default::default()
            },
        )
        .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }
}
