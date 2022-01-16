use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            math_gadget::ShlWordsGadget,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ShlGadget<F> {
    same_context: SameContextGadget<F>,
    shl_words: ShlWordsGadget<F>,
}

impl<F:FieldExt> ExecutionGadget<F> for ShlGadget<F> {
    const NAME: &'static str = "SHL";
    
    const EXECUTION_STATE: ExecutionState = ExecutionState::SHL;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word();
        let shift = cb.query_word();

        cb.stack_pop(shift.expr());
        cb.stack_pop(a.expr());
        let shl_words = ShlWordsGadget::construct(cb, a, shift);
        cb.stack_push(shl_words.b().expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            shl_words,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;
        let indices =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]];
        let [shift, a, b] = indices.map(|idx| block.rws[idx].stack_value());
        self.shl_words.assign(region, offset, a, shift, b)
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        witness,
    };
    use bus_mapping::{bytecode, eth_types::Word, evm::OpcodeId};
    use rand::Rng;

    fn test_ok(opcode: OpcodeId, shift: Word, a: Word) {
        let bytecode = bytecode! {
            PUSH32(a)
            PUSH32(shift)
            #[start]
            .write_op(opcode)
            STOP
        };
        let block = witness::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn shl_gadget_simple() {
        test_ok(OpcodeId::SHL, 0x1.into(), 0x02FF.into());
    }
    
    #[test]
    fn shl_gadget_rand() {
        let a = rand_word();
        let rng = rand::thread_rng();
        let shift = rng.clone().gen_range(0..=255);
        test_ok(OpcodeId::SHL, shift.into(), a);
    }
}