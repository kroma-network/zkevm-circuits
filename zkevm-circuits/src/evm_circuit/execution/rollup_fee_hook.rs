use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::UpdateBalanceGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{AddWordsGadget, MulAddWordsGadget},
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};
use eth_types::{
    kanvas_params::{L1_COST_DENOMINATOR, L1_FEE_RECIPIENT},
    Field, ToLittleEndian, ToScalar,
};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct RollupFeeHookGadget<F> {
    tx_id: Cell<F>,
    l1_base_fee: Word<F>,
    l1_fee_overhead: Word<F>,
    l1_fee_scalar: Word<F>,
    l1_gas_to_use: Word<F>,
    zero: Word<F>,
    l1_fee_tmp: Word<F>,
    l1_fee_tmp2: Word<F>,
    l1_cost_denominator: Word<F>,
    l1_cost_remainder: Word<F>,
    add_rollup_data_gas_by_l1_fee_overhead: AddWordsGadget<F, 2, true>,
    mul_l1_gas_to_use_by_l1_base_fee: MulAddWordsGadget<F>,
    mul_l1_fee_tmp_by_l1_fee_scalar: MulAddWordsGadget<F>,
    div_l1_fee_by_l1_cost_denominator: MulAddWordsGadget<F>,
    l1_fee_recipient: Cell<F>,
    l1_fee_reward: UpdateBalanceGadget<F, 2, true>,
}

impl<F: Field> ExecutionGadget<F> for RollupFeeHookGadget<F> {
    const NAME: &'static str = "RollupFeeHook";

    const EXECUTION_STATE: ExecutionState = ExecutionState::RollupFeeHook;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Add l1 rollup fee to l1_fee_recipient's balance
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let tx_rollup_data_gas_cost =
            cb.tx_context_as_word(tx_id.expr(), TxContextFieldTag::RollupDataGasCost, None);
        let l1_fee_overhead = cb.query_word_rlc();
        let l1_gas_to_use = cb.query_word_rlc();
        let add_rollup_data_gas_by_l1_fee_overhead = AddWordsGadget::construct(
            cb,
            [tx_rollup_data_gas_cost, l1_fee_overhead.clone()],
            l1_gas_to_use.clone(),
        );

        let l1_base_fee = cb.query_word_rlc();
        let zero = cb.query_word_rlc();
        let l1_fee_tmp = cb.query_word_rlc();
        let mul_l1_gas_to_use_by_l1_base_fee =
            MulAddWordsGadget::construct(cb, [&l1_gas_to_use, &l1_base_fee, &zero, &l1_fee_tmp]);
        cb.require_zero(
            "mul_l1_gas_to_use_by_l1_base_fee's overflow == 0",
            mul_l1_gas_to_use_by_l1_base_fee.overflow(),
        );

        let l1_fee_scalar = cb.query_word_rlc();
        let l1_fee_tmp2 = cb.query_word_rlc();
        let mul_l1_fee_tmp_by_l1_fee_scalar =
            MulAddWordsGadget::construct(cb, [&l1_fee_tmp, &l1_fee_scalar, &zero, &l1_fee_tmp2]);
        cb.require_zero(
            "mul_l1_fee_tmp_by_l1_fee_scalar's overflow == 0",
            mul_l1_fee_tmp_by_l1_fee_scalar.overflow(),
        );

        let l1_fee = cb.query_word_rlc();
        let l1_cost_denominator = cb.query_word_rlc();
        let l1_cost_remainder = cb.query_word_rlc();
        // TODO(chokobole): Need to check l1_cost_remainder < l1_cost_denominator
        let div_l1_fee_by_l1_cost_denominator = MulAddWordsGadget::construct(
            cb,
            [
                &l1_fee,
                &l1_cost_denominator,
                &l1_cost_remainder,
                &l1_fee_tmp2,
            ],
        );
        cb.require_zero(
            "div_l1_fee_by_l1_cost_denominator's overflow == 0",
            div_l1_fee_by_l1_cost_denominator.overflow(),
        );

        let l1_fee_recipient = cb.query_cell();
        let l1_fee_reward =
            UpdateBalanceGadget::construct(cb, l1_fee_recipient.expr(), vec![l1_fee], None, None);

        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Delta(2.expr()),
            ..StepStateTransition::any()
        });

        Self {
            tx_id,
            l1_base_fee,
            l1_fee_overhead,
            l1_fee_scalar,
            l1_gas_to_use,
            zero,
            l1_fee_tmp,
            l1_fee_tmp2,
            l1_cost_denominator,
            l1_cost_remainder,
            add_rollup_data_gas_by_l1_fee_overhead,
            mul_l1_gas_to_use_by_l1_base_fee,
            mul_l1_fee_tmp_by_l1_fee_scalar,
            div_l1_fee_by_l1_cost_denominator,
            l1_fee_recipient,
            l1_fee_reward,
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
        let (l1_fee_recipient_balance, l1_fee_recipient_balance_prev) =
            block.rws[step.rw_indices[1]].account_value_pair();

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.l1_base_fee
            .assign(region, offset, Some(block.l1_base_fee.to_le_bytes()))?;
        self.l1_fee_overhead
            .assign(region, offset, Some(block.l1_fee_overhead.to_le_bytes()))?;
        self.l1_fee_scalar
            .assign(region, offset, Some(block.l1_fee_scalar.to_le_bytes()))?;

        let rollup_data_gas_cost = eth_types::Word::from(tx.rollup_data_gas_cost);
        let l1_gas_to_use = rollup_data_gas_cost + block.l1_fee_overhead;
        self.l1_gas_to_use
            .assign(region, offset, Some(l1_gas_to_use.to_le_bytes()))?;
        self.add_rollup_data_gas_by_l1_fee_overhead.assign(
            region,
            offset,
            [rollup_data_gas_cost, block.l1_fee_overhead],
            l1_gas_to_use,
        )?;
        let l1_fee_tmp = l1_gas_to_use * block.l1_base_fee;
        let zero = eth_types::Word::zero();
        self.zero.assign(region, offset, Some(zero.to_le_bytes()))?;
        self.l1_fee_tmp
            .assign(region, offset, Some(l1_fee_tmp.to_le_bytes()))?;
        self.mul_l1_gas_to_use_by_l1_base_fee.assign(
            region,
            offset,
            [l1_gas_to_use, block.l1_base_fee, zero, l1_fee_tmp],
        )?;
        let l1_fee_tmp2 = l1_fee_tmp * block.l1_fee_scalar;
        self.l1_fee_tmp2
            .assign(region, offset, Some(l1_fee_tmp2.to_le_bytes()))?;
        self.mul_l1_fee_tmp_by_l1_fee_scalar.assign(
            region,
            offset,
            [l1_fee_tmp, block.l1_fee_scalar, zero, l1_fee_tmp2],
        )?;
        let l1_cost_denominator = *L1_COST_DENOMINATOR;
        let (l1_fee, l1_cost_remainder) = l1_fee_tmp2.div_mod(l1_cost_denominator);
        self.l1_cost_denominator
            .assign(region, offset, Some(l1_cost_denominator.to_le_bytes()))?;
        self.l1_cost_remainder
            .assign(region, offset, Some(l1_cost_remainder.to_le_bytes()))?;
        self.div_l1_fee_by_l1_cost_denominator.assign(
            region,
            offset,
            [l1_fee, l1_cost_denominator, l1_cost_remainder, l1_fee_tmp2],
        )?;
        self.l1_fee_recipient.assign(
            region,
            offset,
            Value::known(
                L1_FEE_RECIPIENT
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.l1_fee_reward.assign(
            region,
            offset,
            l1_fee_recipient_balance_prev,
            vec![l1_fee],
            l1_fee_recipient_balance,
        )?;

        Ok(())
    }
}
