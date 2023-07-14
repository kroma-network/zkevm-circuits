use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::UpdateBalanceGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{
                ConstantDivisionGadget, IsEqualGadget, MinMaxGadget, MulWordByU64Gadget,
            },
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, RwTableTag, TxContextFieldTag, TxReceiptFieldTag},
    util::Expr,
};
use eth_types::{
    evm_types::MAX_REFUND_QUOTIENT_OF_GAS_USED, geth_types::DEPOSIT_TX_TYPE, Field, ToScalar,
};
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
    max_refund: ConstantDivisionGadget<F, N_BYTES_GAS>,
    refund: Cell<F>,
    effective_refund: MinMaxGadget<F, N_BYTES_GAS>,
    mul_gas_price_by_refund: MulWordByU64Gadget<F>,
    tx_caller_address: Cell<F>,
    gas_fee_refund: UpdateBalanceGadget<F, 2, true>,
}

impl<F: Field> ExecutionGadget<F> for EndDepositTxGadget<F> {
    const NAME: &'static str = "EndDepositTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EndDepositTx;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_persistent = cb.call_context(None, CallContextFieldTag::IsPersistent);

        let [tx_type, tx_gas, tx_caller_address] = [
            TxContextFieldTag::Type,
            TxContextFieldTag::Gas,
            TxContextFieldTag::CallerAddress,
        ]
        .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));
        let tx_gas_price = cb.tx_context_as_word(tx_id.expr(), TxContextFieldTag::GasPrice, None);

        cb.require_equal(
            "this transaction must be deposit tx",
            tx_type.expr(),
            DEPOSIT_TX_TYPE.expr(),
        );

        let is_first_tx = IsEqualGadget::construct(cb, tx_id.expr(), 1.expr());
        let gas_used = tx_gas.expr();

        // Calculate effective gas to refund
        let max_refund = ConstantDivisionGadget::construct(
            cb,
            gas_used.clone(),
            MAX_REFUND_QUOTIENT_OF_GAS_USED as u64,
        );
        let refund = cb.query_cell();
        cb.tx_refund_read(tx_id.expr(), refund.expr());
        let effective_refund = MinMaxGadget::construct(cb, max_refund.quotient(), refund.expr());

        // Add effective_refund * tx_gas_price back to caller's balance
        let mul_gas_price_by_refund =
            MulWordByU64Gadget::construct(cb, tx_gas_price, effective_refund.min());
        let gas_fee_refund = UpdateBalanceGadget::construct(
            cb,
            tx_caller_address.expr(),
            vec![mul_gas_price_by_refund.product().clone()],
            None,
            None,
        );

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
            cb.next.execution_state_selector([
                ExecutionState::BeginTx,
                ExecutionState::BeginDepositTx,
            ]),
            |cb| {
                cb.call_context_lookup(
                    true.expr(),
                    Some(cb.next.state.rw_counter.expr()),
                    CallContextFieldTag::TxId,
                    tx_id.expr() + 1.expr(),
                );

                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(9.expr() - 1.expr() * is_first_tx.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        cb.condition(
            cb.next.execution_state_selector([ExecutionState::EndBlock]),
            |cb| {
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(8.expr() - 1.expr() * is_first_tx.expr()),
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
            max_refund,
            refund,
            effective_refund,
            mul_gas_price_by_refund,
            tx_caller_address,
            gas_fee_refund,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        debug_assert!(tx.transaction_type == DEPOSIT_TX_TYPE);

        let gas_used = tx.gas;
        let (refund, _) = block.rws[step.rw_indices[2]].tx_refund_value_pair();
        let (caller_balance, caller_balance_prev) =
            block.rws[step.rw_indices[3]].account_value_pair();

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

        let (max_refund, _) = self.max_refund.assign(region, offset, gas_used as u128)?;
        self.refund
            .assign(region, offset, Value::known(F::from(refund)))?;
        self.effective_refund.assign(
            region,
            offset,
            F::from(max_refund as u64),
            F::from(refund),
        )?;
        let effective_refund = refund.min(max_refund as u64);
        let gas_fee_refund = tx.gas_price * effective_refund;
        self.mul_gas_price_by_refund.assign(
            region,
            offset,
            tx.gas_price,
            effective_refund,
            gas_fee_refund,
        )?;
        self.tx_caller_address.assign(
            region,
            offset,
            Value::known(
                tx.caller_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.gas_fee_refund.assign(
            region,
            offset,
            caller_balance_prev,
            vec![gas_fee_refund],
            caller_balance,
        )?;
        Ok(())
    }
}
