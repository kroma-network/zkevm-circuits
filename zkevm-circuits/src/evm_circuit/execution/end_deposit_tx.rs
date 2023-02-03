use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::IsEqualGadget,
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{
        CallContextFieldTag, L1BlockFieldTag, RwTableTag, TxContextFieldTag, TxReceiptFieldTag,
    },
    util::Expr,
};
use eth_types::{geth_types::DEPOSIT_TX_TYPE, Field, ToLittleEndian};
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
    l1_base_fee: Word<F>,
    l1_fee_overhead: Word<F>,
    l1_fee_scalar: Word<F>,
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

        let l1_base_fee = cb.query_word();
        let l1_fee_overhead = cb.query_word();
        let l1_fee_scalar = cb.query_word();
        cb.condition(is_first_tx.expr(), |cb| {
            cb.l1_block_lookup(1.expr(), L1BlockFieldTag::L1BaseFee, l1_base_fee.expr());
            cb.l1_block_lookup(
                1.expr(),
                L1BlockFieldTag::L1FeeOverhead,
                l1_fee_overhead.expr(),
            );
            cb.l1_block_lookup(1.expr(), L1BlockFieldTag::L1FeeScalar, l1_fee_scalar.expr());
        });

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
                    rw_counter: Delta(7.expr() + 2.expr() * is_first_tx.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        cb.condition(
            cb.next.execution_state_selector([ExecutionState::EndBlock]),
            |cb| {
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(6.expr() + 2.expr() * is_first_tx.expr()),
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
            l1_base_fee,
            l1_fee_overhead,
            l1_fee_scalar,
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

        self.l1_base_fee
            .assign(region, offset, Some(block.l1_base_fee.to_le_bytes()))?;
        self.l1_fee_overhead
            .assign(region, offset, Some(block.l1_fee_overhead.to_le_bytes()))?;
        self.l1_fee_scalar
            .assign(region, offset, Some(block.l1_fee_scalar.to_le_bytes()))?;

        Ok(())
    }
}
