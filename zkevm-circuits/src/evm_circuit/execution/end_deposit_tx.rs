use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::IsEqualGadget,
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, RwTableTag, TxContextFieldTag, TxReceiptFieldTag},
    util::Expr,
};
use eth_types::{geth_types::DEPOSIT_TX_TYPE, Field};
use halo2_proofs::{circuit::Value, plonk::Error};
use strum::EnumCount;

#[derive(Clone, Debug)]
pub(crate) struct EndDepositTxGadget<F> {
    tx_id: Cell<F>,
    tx_type: Cell<F>,
    tx_gas: Cell<F>,
    current_cumulative_gas_used: Cell<F>,
    is_first_tx: IsEqualGadget<F>,
    is_persistent: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for EndDepositTxGadget<F> {
    const NAME: &'static str = "EndDepositTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EndDepositTx;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_persistent = cb.call_context(None, CallContextFieldTag::IsPersistent);

        let [tx_type, tx_gas] = [TxContextFieldTag::Type, TxContextFieldTag::Gas]
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));

        cb.require_equal(
            "this transaction must be deposit tx",
            tx_type.expr(),
            DEPOSIT_TX_TYPE.expr(),
        );

        let is_first_tx = IsEqualGadget::construct(cb, tx_id.expr(), 1.expr());
        let gas_used = (1.expr() - is_first_tx.expr()) * tx_gas.expr();

        // constrain tx receipt fields
        cb.tx_receipt_lookup(
            1.expr(),
            tx_id.expr(),
            TxReceiptFieldTag::PostStateOrStatus,
            is_persistent.expr(),
        );
        cb.tx_receipt_lookup(
            1.expr(),
            tx_id.expr(),
            TxReceiptFieldTag::LogLength,
            cb.curr.state.log_id.expr(),
        );

        let current_cumulative_gas_used = cb.query_cell();
        cb.condition(is_first_tx.expr(), |cb| {
            cb.require_zero(
                "current_cumulative_gas_used is zero when tx is first tx",
                current_cumulative_gas_used.expr(),
            );
        });

        cb.condition(1.expr() - is_first_tx.expr(), |cb| {
            cb.tx_receipt_lookup(
                0.expr(),
                tx_id.expr() - 1.expr(),
                TxReceiptFieldTag::CumulativeGasUsed,
                current_cumulative_gas_used.expr(),
            );
        });

        cb.tx_receipt_lookup(
            1.expr(),
            tx_id.expr(),
            TxReceiptFieldTag::CumulativeGasUsed,
            gas_used + current_cumulative_gas_used.expr(),
        );

        cb.condition(
            cb.next.execution_state_selector([ExecutionState::BeginTx]),
            |cb| {
                cb.call_context_lookup(
                    true.expr(),
                    Some(cb.next.state.rw_counter.expr()),
                    CallContextFieldTag::TxId,
                    tx_id.expr() + 1.expr(),
                );

                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(7.expr() - is_first_tx.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        cb.condition(
            cb.next.execution_state_selector([ExecutionState::EndBlock]),
            |cb| {
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(6.expr() - is_first_tx.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        Self {
            tx_id,
            tx_type,
            tx_gas,
            current_cumulative_gas_used,
            is_first_tx,
            is_persistent,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        _: &ExecStep,
    ) -> Result<(), Error> {
        debug_assert!(tx.transaction_type == DEPOSIT_TX_TYPE);
        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.tx_type
            .assign(region, offset, Value::known(F::from(tx.transaction_type)))?;
        self.tx_gas
            .assign(region, offset, Value::known(F::from(tx.gas)))?;

        let current_cumulative_gas_used: u64 = if tx.id == 1 {
            0
        } else {
            // first transaction needs TxReceiptFieldTag::COUNT(3) lookups to tx receipt,
            // while later transactions need 4 (with one extra cumulative gas read) lookups
            let rw = &block.rws[(
                RwTableTag::TxReceipt,
                (tx.id - 2) * (TxReceiptFieldTag::COUNT + 1) + 2,
            )];
            rw.receipt_value()
        };

        self.current_cumulative_gas_used.assign(
            region,
            offset,
            Value::known(F::from(current_cumulative_gas_used)),
        )?;
        self.is_first_tx
            .assign(region, offset, F::from(tx.id as u64), F::one())?;
        self.is_persistent.assign(
            region,
            offset,
            Value::known(F::from(call.is_persistent as u64)),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{test::run_test_circuit, witness::block_convert};
    use eth_types::{self, bytecode, geth_types::GethData};
    use mock::{eth, test_ctx::helpers::account_0_code_account_1_no_code, TestContext};

    fn test_ok(block: GethData) {
        let block_data = bus_mapping::mock::BlockData::new_from_geth_data(block);
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&block_data.eth_block, &block_data.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db);

        assert_eq!(run_test_circuit(block), Ok(()));
    }

    #[cfg(feature = "kanvas")]
    #[test]
    fn end_deposit_tx_gadget_simple() {
        // TODO: Enable this with respective code when SSTORE is implemented.
        // Tx with non-capped refund
        // test_ok(vec![mock_tx(
        //     address!("0x00000000000000000000000000000000000000fe"),
        //     Some(27000),
        //     None,
        // )]);
        // Tx with capped refund
        // test_ok(vec![mock_tx(
        //     address!("0x00000000000000000000000000000000000000fe"),
        //     Some(65000),
        //     None,
        // )]);

        use eth_types::geth_types::DEPOSIT_TX_TYPE;
        // Multiple txs
        test_ok(
            // Get the execution steps from the external tracer
            TestContext::<2, 4>::new(
                None,
                account_0_code_account_1_no_code(bytecode! { STOP }),
                |mut txs, accs| {
                    txs[0]
                        .to(accs[0].address)
                        .from(accs[1].address)
                        .transaction_type(DEPOSIT_TX_TYPE);
                    txs[1]
                        .to(accs[0].address)
                        .from(accs[1].address)
                        .value(eth(1));
                    txs[2]
                        .to(accs[0].address)
                        .from(accs[1].address)
                        .value(eth(1));
                    txs[3]
                        .to(accs[0].address)
                        .from(accs[1].address)
                        .value(eth(1));
                },
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap()
            .into(),
        );
    }
}
