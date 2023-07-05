use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_WORD,
        step::ExecutionState,
        util::{
            common_gadget::UpdateBalanceGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{AddWordsGadget, LtWordGadget, MulAddWordsGadget},
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};
use eth_types::{
    kroma_params::{
        BASE_FEE_KEY, L1_BLOCK, L1_COST_DENOMINATOR, L1_FEE_OVERHEAD_KEY, L1_FEE_SCALAR_KEY,
        PROPOSER_REWARD_VAULT,
    },
    Field, ToLittleEndian, ToScalar,
};
use gadgets::util::sum;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct ProposerRewardHookGadget<F> {
    tx_id: Cell<F>,
    base_fee: Word<F>,
    base_fee_committed: Word<F>,
    fee_overhead: Word<F>,
    fee_overhead_committed: Word<F>,
    fee_scalar: Word<F>,
    fee_scalar_committed: Word<F>,
    l1_gas_to_use: Word<F>,
    zero: Word<F>,
    l1_fee_tmp: Word<F>,
    l1_fee_tmp2: Word<F>,
    l1_cost_denominator: Word<F>,
    l1_cost_remainder: Word<F>,
    add_rollup_data_gas_by_fee_overhead: AddWordsGadget<F, 2, true>,
    mul_l1_gas_to_use_by_base_fee: MulAddWordsGadget<F>,
    mul_l1_fee_tmp_by_fee_scalar: MulAddWordsGadget<F>,
    div_l1_fee_by_l1_cost_denominator: MulAddWordsGadget<F>,
    is_remainder_lt_denominator: LtWordGadget<F>,
    proposer_reward_vault: Cell<F>,
    proposer_reward: UpdateBalanceGadget<F, 2, true>,
}

impl<F: Field> ExecutionGadget<F> for ProposerRewardHookGadget<F> {
    const NAME: &'static str = "ProposerRewardHookGadget";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ProposerRewardHook;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let base_fee = cb.query_word_rlc();
        let base_fee_committed = cb.query_word_rlc();
        let fee_overhead = cb.query_word_rlc();
        let fee_overhead_committed = cb.query_word_rlc();
        let fee_scalar = cb.query_word_rlc();
        let fee_scalar_committed = cb.query_word_rlc();

        let l1_block_address = Expression::Constant(
            L1_BLOCK
                .to_scalar()
                .expect("L1 BLOCK should be able to be converted to scalar value"),
        );
        for (i, slot_key) in [*BASE_FEE_KEY, *L1_FEE_OVERHEAD_KEY, *L1_FEE_SCALAR_KEY]
            .iter()
            .enumerate()
        {
            let key_le_bytes = slot_key.to_le_bytes();
            let values = match i {
                0 => Some((base_fee.expr(), base_fee_committed.expr())),
                1 => Some((fee_overhead.expr(), fee_overhead_committed.expr())),
                2 => Some((fee_scalar.expr(), fee_scalar_committed.expr())),
                _ => None,
            };
            if values.is_some() {
                let (value, committed_value) = values.unwrap();
                cb.account_storage_read(
                    l1_block_address.expr(),
                    cb.word_rlc(key_le_bytes.map(|b| b.expr())),
                    value,
                    tx_id.expr(),
                    committed_value,
                );
            }
        }

        // Add l1 rollup fee to proposer_reward_vault's balance
        let tx_rollup_data_gas_cost =
            cb.tx_context_as_word(tx_id.expr(), TxContextFieldTag::RollupDataGasCost, None);
        let l1_gas_to_use = cb.query_word_rlc();
        let add_rollup_data_gas_by_fee_overhead = AddWordsGadget::construct(
            cb,
            [tx_rollup_data_gas_cost, fee_overhead.clone()],
            l1_gas_to_use.clone(),
        );

        // TODO: Instead of being assigned to cell, Can't 0 be used directly?
        let zero = cb.query_word_rlc();
        cb.add_constraint("zero should be zero", sum::expr(&zero.cells));
        let l1_fee_tmp = cb.query_word_rlc();
        let mul_l1_gas_to_use_by_base_fee =
            MulAddWordsGadget::construct(cb, [&l1_gas_to_use, &base_fee, &zero, &l1_fee_tmp]);

        let l1_fee_tmp2 = cb.query_word_rlc();
        let mul_l1_fee_tmp_by_fee_scalar =
            MulAddWordsGadget::construct(cb, [&l1_fee_tmp, &fee_scalar, &zero, &l1_fee_tmp2]);

        let l1_fee = cb.query_word_rlc();
        let l1_cost_denominator = cb.query_word_rlc();
        let l1_cost_remainder = cb.query_word_rlc();
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
        let is_remainder_lt_denominator =
            LtWordGadget::construct(cb, &l1_cost_remainder, &l1_cost_denominator);
        cb.require_true(
            "remainder < denominator",
            is_remainder_lt_denominator.expr(),
        );
        let denominator_array: [Expression<F>; N_BYTES_WORD] = L1_COST_DENOMINATOR
            .to_le_bytes()
            .iter()
            .map(Expr::expr)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        cb.require_equal(
            "l1_cost_denominator == L1_COST_DENOMINATOR(1_000_000)",
            l1_cost_denominator.expr(),
            cb.word_rlc(denominator_array),
        );

        let proposer_reward_vault = cb.query_cell();
        let proposer_reward = UpdateBalanceGadget::construct(
            cb,
            proposer_reward_vault.expr(),
            vec![l1_fee],
            None,
            None,
        );

        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Delta(5.expr()),
            ..StepStateTransition::any()
        });

        Self {
            tx_id,
            base_fee,
            base_fee_committed,
            fee_overhead,
            fee_overhead_committed,
            fee_scalar,
            fee_scalar_committed,
            l1_gas_to_use,
            zero,
            l1_fee_tmp,
            l1_fee_tmp2,
            l1_cost_denominator,
            l1_cost_remainder,
            add_rollup_data_gas_by_fee_overhead,
            mul_l1_gas_to_use_by_base_fee,
            mul_l1_fee_tmp_by_fee_scalar,
            div_l1_fee_by_l1_cost_denominator,
            is_remainder_lt_denominator,
            proposer_reward_vault,
            proposer_reward,
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
        let (base_fee, _, _, base_fee_committed) =
            block.rws[step.rw_indices[1]].storage_value_aux();
        let (fee_overhead, _, _, fee_overhead_committed) =
            block.rws[step.rw_indices[2]].storage_value_aux();
        let (fee_scalar, _, _, fee_scalar_committed) =
            block.rws[step.rw_indices[3]].storage_value_aux();
        let (proposer_reward_vault_balance, proposer_reward_vault_balance_balance_prev) =
            block.rws[step.rw_indices[4]].account_value_pair();

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.base_fee
            .assign(region, offset, Some(base_fee.to_le_bytes()))?;
        self.base_fee_committed
            .assign(region, offset, Some(base_fee_committed.to_le_bytes()))?;
        self.fee_overhead
            .assign(region, offset, Some(fee_overhead.to_le_bytes()))?;
        self.fee_overhead_committed.assign(
            region,
            offset,
            Some(fee_overhead_committed.to_le_bytes()),
        )?;
        self.fee_scalar
            .assign(region, offset, Some(fee_scalar.to_le_bytes()))?;
        self.fee_scalar_committed.assign(
            region,
            offset,
            Some(fee_scalar_committed.to_le_bytes()),
        )?;

        let rollup_data_gas_cost = eth_types::Word::from(tx.rollup_data_gas_cost);
        let l1_gas_to_use = rollup_data_gas_cost + block.l1_fee.fee_overhead;
        self.l1_gas_to_use
            .assign(region, offset, Some(l1_gas_to_use.to_le_bytes()))?;
        self.add_rollup_data_gas_by_fee_overhead.assign(
            region,
            offset,
            [rollup_data_gas_cost, block.l1_fee.fee_overhead],
            l1_gas_to_use,
        )?;
        let l1_fee_tmp = l1_gas_to_use * block.l1_fee.base_fee;
        let zero = eth_types::Word::zero();
        self.zero.assign(region, offset, Some(zero.to_le_bytes()))?;
        self.l1_fee_tmp
            .assign(region, offset, Some(l1_fee_tmp.to_le_bytes()))?;
        self.mul_l1_gas_to_use_by_base_fee.assign(
            region,
            offset,
            [l1_gas_to_use, block.l1_fee.base_fee, zero, l1_fee_tmp],
        )?;
        let l1_fee_tmp2 = l1_fee_tmp * block.l1_fee.fee_scalar;
        self.l1_fee_tmp2
            .assign(region, offset, Some(l1_fee_tmp2.to_le_bytes()))?;
        self.mul_l1_fee_tmp_by_fee_scalar.assign(
            region,
            offset,
            [l1_fee_tmp, block.l1_fee.fee_scalar, zero, l1_fee_tmp2],
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
        self.is_remainder_lt_denominator.assign(
            region,
            offset,
            l1_cost_remainder,
            l1_cost_denominator,
        )?;
        self.proposer_reward_vault.assign(
            region,
            offset,
            Value::known(
                PROPOSER_REWARD_VAULT
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.proposer_reward.assign(
            region,
            offset,
            proposer_reward_vault_balance_balance_prev,
            vec![l1_fee],
            proposer_reward_vault_balance,
        )?;

        Ok(())
    }
}
