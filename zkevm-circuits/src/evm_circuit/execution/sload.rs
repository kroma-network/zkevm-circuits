use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition, Transition::Delta,
            },
            select, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{evm_types::GasCost, Field, ToScalar};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct SloadGadget<F> {
    same_context: SameContextGadget<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    callee_address: Cell<F>,
    phase2_key: Cell<F>,
    phase2_value: Cell<F>,
    phase2_committed_value: Cell<F>,
    is_warm: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for SloadGadget<F> {
    const NAME: &'static str = "SLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SLOAD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);

        let phase2_key = cb.query_cell_phase2();
        // Pop the key from the stack
        cb.stack_pop(phase2_key.expr());

        let phase2_value = cb.query_cell_phase2();
        let phase2_committed_value = cb.query_cell_phase2();
        cb.account_storage_read(
            callee_address.expr(),
            phase2_key.expr(),
            phase2_value.expr(),
            tx_id.expr(),
            phase2_committed_value.expr(),
        );

        cb.stack_push(phase2_value.expr());

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_write(
            tx_id.expr(),
            callee_address.expr(),
            phase2_key.expr(),
            true.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        let gas_cost = SloadGasGadget::construct(cb, is_warm.expr()).expr();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(8.expr()),
            program_counter: Delta(1.expr()),
            reversible_write_counter: Delta(1.expr()),
            gas_left: Delta(-gas_cost),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            tx_id,
            reversion_info,
            callee_address,
            phase2_key,
            phase2_value,
            phase2_committed_value,
            is_warm,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.callee_address.assign(
            region,
            offset,
            Value::known(
                call.callee_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;

        let [key, value] =
            [step.rw_indices[4], step.rw_indices[6]].map(|idx| block.rws[idx].stack_value());
        self.phase2_key
            .assign(region, offset, region.word_rlc(key))?;
        self.phase2_value
            .assign(region, offset, region.word_rlc(value))?;

        let (_, committed_value) = block.rws[step.rw_indices[5]].aux_pair();
        self.phase2_committed_value
            .assign(region, offset, region.word_rlc(committed_value))?;

        let (_, is_warm) = block.rws[step.rw_indices[7]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SloadGasGadget<F> {
    is_warm: Expression<F>,
    gas_cost: Expression<F>,
}

impl<F: Field> SloadGasGadget<F> {
    pub(crate) fn construct(_cb: &mut ConstraintBuilder<F>, is_warm: Expression<F>) -> Self {
        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_SLOAD.expr(),
        );

        Self { is_warm, gas_cost }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }
}

#[cfg(test)]
mod test {

    use crate::{
        evm_circuit::test::rand_word,
        test_util::{run_test_circuits, BytecodeTestConfig},
    };

    use eth_types::{bytecode, Word};
    #[cfg(feature = "kanvas")]
    use mock::test_ctx::helpers::setup_kanvas_required_accounts;
    use mock::{test_ctx::helpers::tx_from_1_to_0, SimpleTestContext, MOCK_ACCOUNTS};

    fn test_ok(key: Word, value: Word) {
        // Here we use two bytecodes to test both is_persistent(STOP) or not(REVERT)
        // Besides, in bytecode we use two SLOADs,
        // the first SLOAD is used to test cold,  and the second is used to test warm
        let bytecode_success = bytecode! {
            PUSH32(key)
            SLOAD
            PUSH32(key)
            SLOAD
            STOP
        };
        let bytecode_failure = bytecode! {
            PUSH32(key)
            SLOAD
            PUSH32(key)
            SLOAD
            PUSH32(0)
            PUSH32(0)
            REVERT
        };
        for bytecode in [bytecode_success, bytecode_failure] {
            let ctx = SimpleTestContext::new(
                None,
                #[allow(unused_mut)]
                |mut accs| {
                    accs[0]
                        .address(MOCK_ACCOUNTS[0])
                        .balance(Word::from(10u64.pow(19)))
                        .code(bytecode)
                        .storage(vec![(key, value)].into_iter());
                    accs[1]
                        .address(MOCK_ACCOUNTS[1])
                        .balance(Word::from(10u64.pow(19)));
                    #[cfg(feature = "kanvas")]
                    setup_kanvas_required_accounts(accs.as_mut_slice(), 2);
                },
                tx_from_1_to_0,
                |block, _txs| block,
            )
            .unwrap();
            let test_config = BytecodeTestConfig {
                enable_state_circuit_test: true,
                ..Default::default()
            };
            assert_eq!(run_test_circuits(ctx, Some(test_config),), Ok(()));
        }
    }

    #[test]
    fn sload_gadget_simple() {
        let key = 0x030201.into();
        let value = 0x060504.into();
        test_ok(key, value);
    }

    #[test]
    fn sload_gadget_rand() {
        let key = rand_word();
        let value = rand_word();
        test_ok(key, value);
    }
}
