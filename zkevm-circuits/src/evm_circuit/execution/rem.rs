use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            math_gadget::DivWordsGadget,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ModGadget<F> {
    same_context: SameContextGadget<F>,
    div_words: DivWordsGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for ModGadget<F> {
    const NAME: &'static str = "MOD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MOD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let dividend = cb.query_word();
        let divisor = cb.query_word();
        let div_words =
            DivWordsGadget::construct(cb, dividend.clone(), divisor.clone());

        cb.stack_pop(dividend.expr());
        cb.stack_pop(divisor.expr());
        cb.stack_push(div_words.remainder().expr());

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
            div_words,
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
        let [dividend, divisor, remainder] =
            indices.map(|idx| block.rws[idx].stack_value());
        let quotient = (dividend - remainder) / divisor;
        self.div_words
            .assign(region, offset, dividend, divisor, quotient, remainder)
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        witness,
    };
    use bus_mapping::{bytecode, eth_types::Word, evm::OpcodeId};

    fn test_ok(opcode: OpcodeId, dividend: Word, divisor: Word) {
        let bytecode = bytecode! {
            PUSH32(divisor)
            PUSH32(dividend)
            #[start]
            .write_op(opcode)
            STOP
        };
        let block = witness::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn mod_gadget_simple() {
        test_ok(OpcodeId::MOD, 0xFFFFFF.into(), 0xABC.into());
        test_ok(OpcodeId::MOD, 0xFFFFFF.into(), 0xFFF.into());
        test_ok(
            OpcodeId::MOD,
            Word::from_big_endian(&[255u8; 32]),
            0xABCDEF.into(),
        );
    }

    #[test]
    fn mod_gadget_rand() {
        let dividend = rand_word();
        let divisor = rand_word();
        test_ok(OpcodeId::MOD, dividend, divisor);
    }
}
