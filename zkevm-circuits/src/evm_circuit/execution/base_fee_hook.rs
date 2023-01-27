use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::UpdateBalanceGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::MulWordByU64Gadget,
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{BlockContextFieldTag, CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};
use eth_types::{kanvas_params::BASE_FEE_RECIPIENT, Field, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct BaseFeeHookGadget<F> {
    tx_id: Cell<F>,
    tx_gas: Cell<F>,
    mul_base_fee_by_gas_used: MulWordByU64Gadget<F>,
    base_fee_recipient: Cell<F>,
    base_fee_reward: UpdateBalanceGadget<F, 2, true>,
}

impl<F: Field> ExecutionGadget<F> for BaseFeeHookGadget<F> {
    const NAME: &'static str = "BaseFeeHook";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BaseFeeHook;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let tx_gas = cb.tx_context(tx_id.expr(), TxContextFieldTag::Gas, None);

        // Add gas_used * base_fee to base_fee_recipient's balance
        let base_fee = cb.query_word();
        cb.block_lookup(
            BlockContextFieldTag::BaseFee.expr(),
            cb.curr.state.block_number.expr(),
            base_fee.expr(),
        );
        let gas_used = tx_gas.expr() - cb.curr.state.gas_left.expr();
        let mul_base_fee_by_gas_used = MulWordByU64Gadget::construct(cb, base_fee, gas_used);

        let base_fee_recipient = cb.query_cell();
        let base_fee_reward = UpdateBalanceGadget::construct(
            cb,
            base_fee_recipient.expr(),
            vec![mul_base_fee_by_gas_used.product().clone()],
            None,
            None,
        );

        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Delta(2.expr()),
            ..StepStateTransition::any()
        });

        Self {
            tx_id,
            tx_gas,
            mul_base_fee_by_gas_used,
            base_fee_recipient,
            base_fee_reward,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let (base_fee_recipient_balance, base_fee_recipient_balance_prev) =
            block.rws[step.rw_indices[1]].account_value_pair();

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.tx_gas
            .assign(region, offset, Value::known(F::from(tx.gas)))?;

        let context = &block.context.ctxs[&tx.block_number];
        let gas_used = tx.gas - step.gas_left;
        let base_fee_reward = context.base_fee * gas_used;
        self.mul_base_fee_by_gas_used.assign(
            region,
            offset,
            context.base_fee,
            gas_used,
            base_fee_reward,
        )?;
        self.base_fee_recipient.assign(
            region,
            offset,
            Value::known(
                BASE_FEE_RECIPIENT
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.base_fee_reward.assign(
            region,
            offset,
            base_fee_recipient_balance_prev,
            vec![base_fee_reward],
            base_fee_recipient_balance,
        )?;

        Ok(())
    }
}
