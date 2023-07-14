#[cfg(test)]
mod number_tests {
    use crate::{
        circuit_input_builder::ExecState,
        evm::OpcodeId,
        mock::BlockData,
        operation::{StackOp, RW},
        Error,
    };
    use eth_types::{bytecode, evm_types::StackAddress, geth_types::GethData};
    use mock::{
        test_ctx::{
            helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
            SimpleTestContext,
        },
        tx_idx,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn number_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            #[start]
            NUMBER
            STOP
        };
        let block_number = 0xcafeu64;
        // Get the execution steps from the external tracer
        let block: GethData = SimpleTestContext::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(block_number),
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::NUMBER))
            .unwrap();

        let call_id = builder.block.txs()[tx_idx!(0)].calls[0].call_id;

        let op_number = &builder.block.container.stack[step.bus_mapping_instance[0].as_usize()];

        assert_eq!(
            (op_number.rw(), op_number.op()),
            (
                RW::WRITE,
                &StackOp::new(call_id, StackAddress(1023usize), block_number.into())
            )
        );

        Ok(())
    }
}
