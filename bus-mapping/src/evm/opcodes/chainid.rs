#[cfg(test)]

mod chainid_tests {
    use crate::operation::RW;
    use crate::{circuit_input_builder::ExecState, mock::BlockData, operation::StackOp};
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
    };

    use mock::test_ctx::helpers::*;
    use mock::{tx_idx, SimpleTestContext, MOCK_CHAIN_ID};
    use pretty_assertions::assert_eq;

    #[test]
    fn chainid_opcode_impl() {
        let code = bytecode! {
            CHAINID
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = SimpleTestContext::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block,
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CHAINID))
            .unwrap();

        let call_id = builder.block.txs()[tx_idx!(0)].calls()[0].call_id;

        assert_eq!(
            {
                let operation =
                    &builder.block.container.stack[step.bus_mapping_instance[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &StackOp::new(call_id, StackAddress::from(1023), *MOCK_CHAIN_ID)
            )
        );
    }
}
