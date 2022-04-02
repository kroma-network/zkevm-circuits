use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, Same},
            },
            Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct StopGadget<F> {
    opcode: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for StopGadget<F> {
    const NAME: &'static str = "STOP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::STOP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // TODO: Check if opcode fetching is out of range.
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        // Call ends with STOP must be successful
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 1.expr());

        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr() + is_to_end_tx.clone(),
            2.expr() * cb.curr.state.is_root.expr() * is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // When a transaction ends with STOP, this call must be persistent
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::IsPersistent,
                1.expr(),
            );

            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(2.expr()),
                ..StepStateTransition::any()
            });
        });

        // When it's an internal call
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(cb, Delta(13.expr()), 0.expr(), 0.expr())
        });

        Self {
            opcode,
            restore_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Some(F::from(opcode.as_u64())))?;

        self.restore_context
            .assign(region, offset, block, call, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::run_test_circuit_incomplete_fixed_table, witness::block_convert,
    };
    use eth_types::{address, bytecode, Bytecode, Word};
    use itertools::Itertools;
    use mock::TestContext;

    fn test_ok(bytecode: Bytecode, is_root: bool) {
        let block_data = if is_root {
            bus_mapping::mock::BlockData::new_from_geth_data(
                TestContext::<2, 1>::new(
                    None,
                    |accs| {
                        accs[0]
                            .address(address!("0x0000000000000000000000000000000000000000"))
                            .balance(Word::from(1u64 << 30));
                        accs[1]
                            .address(address!("0x0000000000000000000000000000000000000010"))
                            .balance(Word::from(1u64 << 20))
                            .code(bytecode);
                    },
                    |mut txs, accs| {
                        txs[0]
                            .from(accs[0].address)
                            .to(accs[1].address)
                            .gas(Word::from(30000));
                    },
                    |block, _tx| block.number(0xcafeu64),
                )
                .unwrap()
                .into(),
            )
        } else {
            bus_mapping::mock::BlockData::new_from_geth_data(
                TestContext::<3, 1>::new(
                    None,
                    |accs| {
                        accs[0]
                            .address(address!("0x0000000000000000000000000000000000000000"))
                            .balance(Word::from(1u64 << 30));
                        accs[1]
                            .address(address!("0x0000000000000000000000000000000000000010"))
                            .balance(Word::from(1u64 << 20))
                            .code(bytecode! {
                                PUSH1(0)
                                PUSH1(0)
                                PUSH1(0)
                                PUSH1(0)
                                PUSH1(0)
                                PUSH1(0x20)
                                GAS
                                CALL
                                STOP
                            });
                        accs[2]
                            .address(address!("0x0000000000000000000000000000000000000020"))
                            .balance(Word::from(1u64 << 20))
                            .code(bytecode);
                    },
                    |mut txs, accs| {
                        txs[0]
                            .from(accs[0].address)
                            .to(accs[1].address)
                            .gas(Word::from(30000));
                    },
                    |block, _tx| block.number(0xcafeu64),
                )
                .unwrap()
                .into(),
            )
        };
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&block_data.eth_block, &block_data.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn stop_gadget_simple() {
        let bytecodes = vec![
            bytecode! {
                PUSH1(0)
                STOP
            },
            /* TODO: Enable this when opcode fetching out of range is handled
             * bytecode! {
             *     PUSH1(0)
             * }, */
        ];
        let is_roots = vec![true, false];
        for (bytecode, is_root) in bytecodes.into_iter().cartesian_product(is_roots) {
            test_ok(bytecode, is_root);
        }
    }
}
