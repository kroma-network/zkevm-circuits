use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::CallContextField,
    Error,
};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::PC`](crate::evm::OpcodeId::PC) `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct GasPrice;

impl Opcode for GasPrice {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        // Get gasprice result from next step
        let value = geth_steps[1].stack.last()?;
        let tx_id = state.tx_ctx.id();

        // CallContext read of the TxId
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            tx_id.into(),
        );

        // Stack write of the gasprice value
        state.stack_write(
            &mut exec_step,
            geth_step.stack.last_filled().map(|a| a - 1),
            value,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod gasprice_tests {
    use crate::{
        circuit_input_builder::ExecState,
        evm::OpcodeId,
        mock::BlockData,
        operation::{CallContextField, CallContextOp, StackOp, RW},
        Error,
    };
    use eth_types::{bytecode, evm_types::StackAddress, geth_types::GethData, Word};
    use mock::{
        test_ctx::{
            helpers::{account_0_code_account_1_no_code, system_deposit_tx},
            SimpleTestContext,
        },
        tx_idx,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn gasprice_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            #[start]
            GASPRICE
            STOP
        };

        let two_gwei = Word::from(2_000_000_000u64);

        // Get the execution steps from the external tracer
        let block: GethData = SimpleTestContext::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                #[cfg(feature = "kroma")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas_price(two_gwei);
            },
            |block, _tx| block.number(0xcafeu64),
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::GASPRICE))
            .unwrap();
        let call_id = builder.block.txs()[tx_idx!(0)].calls[0].call_id;

        let op_gasprice = &builder.block.container.stack[step.bus_mapping_instance[1].as_usize()];
        assert_eq!(
            (op_gasprice.rw(), op_gasprice.op()),
            (
                RW::WRITE,
                &StackOp::new(call_id, StackAddress(1023usize), two_gwei)
            )
        );

        assert_eq!(
            {
                let operation =
                    &builder.block.container.call_context[step.bus_mapping_instance[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::TxId,
                    value: Word::from(tx_idx!(1)),
                }
            )
        );

        Ok(())
    }
}
