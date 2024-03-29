use super::ExecutionGadget;
use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        step::ExecutionState,
        util::{
            common_gadget::UpdateBalanceGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{AddWordsGadget, LtWordGadget, MulAddWordsGadget, MulWordByU64Gadget},
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};
use eth_types::{
    kroma_params::{
        L1_BLOCK, PROTOCOL_VAULT, REWARD_DENOMINATOR, VALIDATOR_REWARD_SCALAR_KEY,
        VALIDATOR_REWARD_VAULT,
    },
    Field, ToLittleEndian, ToScalar, U256,
};
use gadgets::util::sum;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct FeeDistributionHookGadget<F> {
    tx_id: Cell<F>,
    tx_gas: Cell<F>,
    validator_reward_scalar: Word<F>,
    validator_reward_scalar_committed: Word<F>,
    mul_gas_used_by_tx_gas_price: MulWordByU64Gadget<F>,
    zero: Word<F>,
    validator_reward_tmp: Word<F>, // tx_gas_price * gas_used * validator_reward_scalar
    mul_total_reward_by_reward_scalar: MulAddWordsGadget<F>,
    remainder: Word<F>,
    reward_denominator: Word<F>,
    div_validator_reward_tmp_by_reward_denominator: MulAddWordsGadget<F>,
    is_remainder_lt_denominator: LtWordGadget<F>,
    protocol_reward_vault: Cell<F>,
    protocol_received_reward: UpdateBalanceGadget<F, 2, true>,
    validator_reward_vault: Cell<F>,
    validator_received_reward: UpdateBalanceGadget<F, 2, true>,
    sum_protocol_validator_rewards: AddWordsGadget<F, 2, true>,
}

impl<F: Field> ExecutionGadget<F> for FeeDistributionHookGadget<F> {
    const NAME: &'static str = "FeeDistributionHook";

    const EXECUTION_STATE: ExecutionState = ExecutionState::FeeDistributionHook;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let tx_gas = cb.tx_context(tx_id.expr(), TxContextFieldTag::Gas, None);
        let gas_used = tx_gas.expr() - cb.curr.state.gas_left.expr();
        let tx_gas_price = cb.tx_context_as_word(tx_id.expr(), TxContextFieldTag::GasPrice, None);

        let l1_block_address = Expression::Constant(
            L1_BLOCK
                .to_scalar()
                .expect("L1 BLOCK should be able to be converted to scalar value"),
        );
        let validator_reward_scalar = cb.query_word_rlc();
        let validator_reward_scalar_committed = cb.query_word_rlc();
        let key_le_bytes: [u8; 32] = (*VALIDATOR_REWARD_SCALAR_KEY).to_le_bytes();
        cb.account_storage_read(
            l1_block_address.expr(),
            cb.word_rlc(key_le_bytes.map(|b| b.expr())),
            validator_reward_scalar.expr(),
            tx_id.expr(),
            validator_reward_scalar_committed.expr(),
        );

        // tx_gas_price * gas_used
        let mul_gas_used_by_tx_gas_price =
            MulWordByU64Gadget::construct(cb, tx_gas_price, gas_used);
        let total_reward = mul_gas_used_by_tx_gas_price.product();
        // TODO: Instead of being assigned to cell, Can't 0 be used directly?
        let zero = cb.query_word_rlc();
        cb.add_constraint("zero should be zero", sum::expr(&zero.cells));
        let validator_reward_tmp = cb.query_word_rlc();
        let mul_total_reward_by_reward_scalar = MulAddWordsGadget::construct(
            cb,
            [
                total_reward,
                &validator_reward_scalar,
                &zero,
                &validator_reward_tmp,
            ],
        );

        // gas_used * tx_gas_price * validator_reward_scalar / REWARD_DENOMINATOR
        let validator_reward = cb.query_word_rlc();
        let remainder = cb.query_word_rlc();
        // TODO: Instead of being assigned to cell, Can't REWEARD_DENOMINATOR be used directly?
        let reward_denominator = cb.query_word_rlc();

        let div_validator_reward_tmp_by_reward_denominator = MulAddWordsGadget::construct(
            cb,
            [
                &validator_reward,
                &reward_denominator,
                &remainder,
                &validator_reward_tmp,
            ],
        );
        cb.require_zero(
            "div_validator_reward_tmp_by_reward_denominator's overflow == 0",
            div_validator_reward_tmp_by_reward_denominator.overflow(),
        );
        let is_remainder_lt_denominator =
            LtWordGadget::construct(cb, &remainder, &reward_denominator);
        cb.require_true(
            "remainder < denominator",
            is_remainder_lt_denominator.expr(),
        );
        let denominator_array: [Expression<F>; N_BYTES_WORD] = REWARD_DENOMINATOR
            .to_le_bytes()
            .iter()
            .map(Expr::expr)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        cb.require_equal(
            "reward_denominator == REWARD_DENOMINATOR(10000)",
            reward_denominator.expr(),
            cb.word_rlc(denominator_array),
        );

        // protocol reward
        let protocol_reward = cb.query_word_rlc();
        let protocol_reward_vault = cb.query_cell();
        let protocol_received_reward = UpdateBalanceGadget::construct(
            cb,
            protocol_reward_vault.expr(),
            vec![protocol_reward.clone()],
            None,
            None,
        );

        // validator reward
        let validator_reward_vault = cb.query_cell();
        let validator_received_reward = UpdateBalanceGadget::construct(
            cb,
            validator_reward_vault.expr(),
            vec![validator_reward.clone()],
            None,
            None,
        );

        // checking total_reward = protocol_reward + validator_reward
        let sum_protocol_validator_rewards = AddWordsGadget::construct(
            cb,
            [protocol_reward, validator_reward],
            total_reward.clone(),
        );

        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Delta(4.expr()),
            ..StepStateTransition::any()
        });

        Self {
            tx_id,
            tx_gas,
            validator_reward_scalar,
            validator_reward_scalar_committed,
            mul_gas_used_by_tx_gas_price,
            zero,
            validator_reward_tmp,
            mul_total_reward_by_reward_scalar,
            remainder,
            reward_denominator,
            div_validator_reward_tmp_by_reward_denominator,
            is_remainder_lt_denominator,
            validator_reward_vault,
            validator_received_reward,
            protocol_reward_vault,
            protocol_received_reward,
            sum_protocol_validator_rewards,
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
        let (protocol_reward_vault_balance, protocol_reward_vault_balance_prev) =
            block.rws[step.rw_indices[2]].account_value_pair();
        let (validator_reward_vault_balance, validator_reward_vault_balance_prev) =
            block.rws[step.rw_indices[3]].account_value_pair();

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.tx_gas
            .assign(region, offset, Value::known(F::from(tx.gas)))?;
        let validator_reward_scalar = block.l1_fee.validator_reward_scalar;
        self.validator_reward_scalar.assign(
            region,
            offset,
            Some(validator_reward_scalar.to_le_bytes()),
        )?;
        self.validator_reward_scalar_committed.assign(
            region,
            offset,
            Some(block.l1_fee_committed.validator_reward_scalar.to_le_bytes()),
        )?;

        let gas_used = tx.gas - step.gas_left;
        let total_reward = U256::from(gas_used) * tx.gas_price;

        // tx_gas_price * gas_used
        self.mul_gas_used_by_tx_gas_price.assign(
            region,
            offset,
            tx.gas_price,
            gas_used,
            total_reward,
        )?;

        // tx_gas_price * gas_used * validator_reward_scalar
        let validator_reward_tmp = total_reward * validator_reward_scalar;
        let zero = eth_types::Word::zero();
        self.zero.assign(region, offset, Some(zero.to_le_bytes()))?;
        self.validator_reward_tmp.assign(
            region,
            offset,
            Some(validator_reward_tmp.to_le_bytes()),
        )?;
        self.mul_total_reward_by_reward_scalar.assign(
            region,
            offset,
            [
                total_reward,
                validator_reward_scalar,
                zero,
                validator_reward_tmp,
            ],
        )?;

        // gas_used * tx_gas_price * validator_reward_scalar / REWARD_DENOMINATOR
        let (validator_reward, remainder) = validator_reward_tmp.div_mod(*REWARD_DENOMINATOR);
        let protocol_reward = total_reward - validator_reward;

        self.remainder
            .assign(region, offset, Some(remainder.to_le_bytes()))?;
        self.reward_denominator
            .assign(region, offset, Some(REWARD_DENOMINATOR.to_le_bytes()))?;
        self.div_validator_reward_tmp_by_reward_denominator.assign(
            region,
            offset,
            [
                validator_reward,
                *REWARD_DENOMINATOR,
                remainder,
                validator_reward_tmp,
            ],
        )?;
        self.is_remainder_lt_denominator
            .assign(region, offset, remainder, *REWARD_DENOMINATOR)?;

        self.protocol_received_reward.assign(
            region,
            offset,
            protocol_reward_vault_balance_prev,
            vec![protocol_reward],
            protocol_reward_vault_balance,
        )?;

        // protocol reward
        self.protocol_reward_vault.assign(
            region,
            offset,
            Value::known(
                PROTOCOL_VAULT
                    .to_scalar()
                    .expect("unexpected Address(PROTOCOL_VAULT) -> Scalar conversion failure"),
            ),
        )?;

        // validator reward
        self.validator_reward_vault.assign(
            region,
            offset,
            Value::known(
                VALIDATOR_REWARD_VAULT.to_scalar().expect(
                    "unexpected Address(VALIDATOR_REWARD_VAULT) -> Scalar conversion failure",
                ),
            ),
        )?;
        self.validator_received_reward.assign(
            region,
            offset,
            validator_reward_vault_balance_prev,
            vec![validator_reward],
            validator_reward_vault_balance,
        )?;

        self.sum_protocol_validator_rewards.assign(
            region,
            offset,
            [protocol_reward, validator_reward],
            total_reward,
        )?;

        Ok(())
    }
}
