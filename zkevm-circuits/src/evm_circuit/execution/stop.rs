#[cfg(feature = "kroma")]
use crate::{evm_circuit::util::math_gadget::IsEqualGadget, table::TxContextFieldTag};
use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, Same},
            },
            math_gadget::IsZeroGadget,
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
#[cfg(feature = "kroma")]
use eth_types::geth_types::DEPOSIT_TX_TYPE;
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct StopGadget<F> {
    code_length: Cell<F>,
    is_out_of_range: IsZeroGadget<F>,
    opcode: Cell<F>,
    restore_context: RestoreContextGadget<F>,
    #[cfg(feature = "kroma")]
    tx_id: Cell<F>,
    #[cfg(feature = "kroma")]
    tx_type: Cell<F>,
    #[cfg(feature = "kroma")]
    is_deposit_tx: IsEqualGadget<F>,
}

fn stop_rwc<F: Field>(success: bool) -> Expression<F> {
    let base = 1 + if success { 1 } else { 0 };
    #[cfg(feature = "kroma")]
    return (base + 1).expr();
    #[cfg(not(feature = "kroma"))]
    return base.expr();
}

impl<F: Field> ExecutionGadget<F> for StopGadget<F> {
    const NAME: &'static str = "STOP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::STOP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let code_length = cb.query_cell();
        cb.bytecode_length(cb.curr.state.code_hash.expr(), code_length.expr());
        let is_out_of_range = IsZeroGadget::construct(
            cb,
            code_length.expr() - cb.curr.state.program_counter.expr(),
        );
        let opcode = cb.query_cell();
        // cb.condition(1.expr() - is_out_of_range.expr(), |cb| {
        // cb.opcode_lookup(opcode.expr(), 1.expr());
        // });

        // We do the responsible opcode check explicitly here because we're not using
        // the `SameContextGadget` for `STOP`.
        cb.require_equal(
            "Opcode should be STOP",
            opcode.expr(),
            OpcodeId::STOP.expr(),
        );

        // Call ends with STOP must be successful
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 1.expr());

        #[cfg(feature = "kroma")]
        // Lookup in call_ctx the TxId
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        #[cfg(feature = "kroma")]
        // Lookup the tx_type in tx table
        let tx_type = cb.tx_context(tx_id.expr(), TxContextFieldTag::Type, None);
        #[cfg(feature = "kroma")]
        let is_deposit_tx = IsEqualGadget::construct(cb, tx_type.expr(), DEPOSIT_TX_TYPE.expr());
        #[cfg(feature = "kroma")]
        StopGadget::constrain_state_transition(cb, is_deposit_tx.expr());
        #[cfg(not(feature = "kroma"))]
        StopGadget::constrain_state_transition(cb);

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            #[cfg(feature = "kroma")]
            let rwc = 2.expr();
            #[cfg(not(feature = "kroma"))]
            let rwc = 1.expr();

            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(rwc),
                ..StepStateTransition::any()
            });
        });

        // When it's an internal call
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                true.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        Self {
            code_length,
            is_out_of_range,
            opcode,
            restore_context,
            #[cfg(feature = "kroma")]
            tx_id,
            #[cfg(feature = "kroma")]
            tx_type,
            #[cfg(feature = "kroma")]
            is_deposit_tx,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let code = block
            .bytecodes
            .get(&call.code_hash)
            .expect("could not find current environment's bytecode");
        self.code_length.assign(
            region,
            offset,
            Value::known(F::from(code.bytes.len() as u64)),
        )?;

        self.is_out_of_range.assign(
            region,
            offset,
            F::from(code.bytes.len() as u64) - F::from(step.program_counter),
        )?;

        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        if !call.is_root {
            #[cfg(feature = "kroma")]
            let rw_offset = 2;
            #[cfg(not(feature = "kroma"))]
            let rw_offset = 1;
            self.restore_context
                .assign(region, offset, block, call, step, rw_offset)?;
        }

        #[cfg(feature = "kroma")]
        self.tx_id
            .assign(region, offset, Value::known(F::from(_tx.id as u64)))?;

        #[cfg(feature = "kroma")]
        self.tx_type
            .assign(region, offset, Value::known(F::from(_tx.transaction_type)))?;

        #[cfg(feature = "kroma")]
        self.is_deposit_tx.assign(
            region,
            offset,
            F::from(_tx.transaction_type),
            F::from(DEPOSIT_TX_TYPE),
        )?;

        Ok(())
    }
}

impl<F: Field> StopGadget<F> {
    #[cfg(feature = "kroma")]
    fn constrain_state_transition(cb: &mut ConstraintBuilder<F>, is_deposit_tx: Expression<F>) {
        cb.condition(is_deposit_tx.expr(), |cb| {
            let is_to_end_deposit_tx = cb
                .next
                .execution_state_selector([ExecutionState::EndDepositTx]);
            cb.require_equal(
                "Go to EndDepositTx only when is_root",
                cb.curr.state.is_root.expr(),
                is_to_end_deposit_tx,
            );
        });
        cb.condition(1.expr() - is_deposit_tx.expr(), |cb| {
            let is_to_fee_distribution_hook = cb
                .next
                .execution_state_selector([ExecutionState::FeeDistributionHook]);
            cb.require_equal(
                "Go to FeeDistributionHook only when is_root",
                cb.curr.state.is_root.expr(),
                is_to_fee_distribution_hook,
            );
        });
    }

    #[cfg(not(feature = "kroma"))]
    fn constrain_state_transition(cb: &mut ConstraintBuilder<F>) {
        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{address, bytecode, Bytecode, Word};

    use itertools::Itertools;
    #[cfg(feature = "kroma")]
    use mock::test_ctx::helpers::{setup_kroma_required_accounts, system_deposit_tx};
    use mock::{
        test_ctx::{SimpleTestContext, TestContext3_1},
        tx_idx,
    };

    fn test_ok(bytecode: Bytecode, is_root: bool) {
        if is_root {
            let ctx = SimpleTestContext::new(
                None,
                |mut accs| {
                    accs[0]
                        .address(address!("0x0000000000000000000000000000000000000123"))
                        .balance(Word::from(1u64 << 30));
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000010"))
                        .balance(Word::from(1u64 << 20))
                        .code(bytecode);
                    #[cfg(feature = "kroma")]
                    setup_kroma_required_accounts(accs.as_mut_slice(), 2);
                },
                |mut txs, accs| {
                    #[cfg(feature = "kroma")]
                    system_deposit_tx(txs[0]);
                    txs[tx_idx!(0)]
                        .from(accs[0].address)
                        .to(accs[1].address)
                        .gas(Word::from(30000));
                },
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        } else {
            let ctx = TestContext3_1::new(
                None,
                |mut accs| {
                    accs[0]
                        .address(address!("0x0000000000000000000000000000000000000123"))
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
                    #[cfg(feature = "kroma")]
                    setup_kroma_required_accounts(accs.as_mut_slice(), 3);
                },
                |mut txs, accs| {
                    #[cfg(feature = "kroma")]
                    system_deposit_tx(txs[0]);
                    txs[tx_idx!(0)]
                        .from(accs[0].address)
                        .to(accs[1].address)
                        .gas(Word::from(30000));
                },
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        };
    }

    #[test]
    fn stop_gadget_simple() {
        let bytecodes = vec![
            bytecode! {
                PUSH1(0)
                STOP
            },
            bytecode! {
                PUSH1(0)
            },
        ];
        let is_roots = vec![true, false];
        for (bytecode, is_root) in bytecodes.into_iter().cartesian_product(is_roots) {
            test_ok(bytecode, is_root);
        }
    }
}
