use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag},
        util::{
            common_gadget::RestoreContextGadget, constraint_builder::ConstraintBuilder, not,
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ReturnGadget<F> {
    opcode: Cell<F>,

    length: Word<F>,
    offset: Word<F>,

    is_root: Cell<F>,
    is_create: Cell<F>,
    is_success: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

// This will handle reverts too?
impl<F: Field> ExecutionGadget<F> for ReturnGadget<F> {
    const NAME: &'static str = "RETURN";

    const EXECUTION_STATE: ExecutionState = ExecutionState::RETURN;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        let length = cb.query_rlc::<32>();
        let offset = cb.query_rlc::<32>();
        cb.stack_pop(length.expr()); // +1
        cb.stack_pop(offset.expr()); // +2

        let is_root = cb.call_context(None, CallContextFieldTag::IsRoot); // +3
        let is_create = cb.call_context(None, CallContextFieldTag::IsCreate); // +4
        let is_success = cb.call_context(None, CallContextFieldTag::IsSuccess); // +5

        cb.condition(is_success.expr(), |cb| {
            cb.require_equal(
                "Opcode should be RETURN",
                opcode.expr(),
                OpcodeId::RETURN.expr(),
            )
        });
        cb.condition(not::expr(is_success.expr()), |cb| {
            cb.require_equal(
                "Opcode should be REVERT",
                opcode.expr(),
                OpcodeId::REVERT.expr(),
            )
        });

        cb.condition(is_root.expr(), |cb| {
            cb.require_next_state(ExecutionState::EndTx);
            cb.call_context_lookup(
                0.expr(),
                None,
                CallContextFieldTag::IsSuccess,
                is_success.expr(),
            );
        });
        let restore_context = cb.condition(not::expr(is_root.expr()), |cb| {
            cb.require_next_state_not(ExecutionState::EndTx);
            RestoreContextGadget::construct(cb, offset.expr(), length.expr())
        });

        Self {
            opcode,
            length,
            offset,
            is_root,
            is_create,
            is_success,
            restore_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.opcode.assign(
            region,
            offset,
            step.opcode.map(|opcode| F::from(opcode.as_u64())),
        )?;

        let length = block.rws[step.rw_indices[0]].stack_value();
        self.length
            .assign(region, offset, Some(length.to_le_bytes()))?;

        let memory_offset = block.rws[step.rw_indices[1]].stack_value();
        self.offset
            .assign(region, offset, Some(memory_offset.to_le_bytes()))?;

        self.is_root.assign(
            region,
            offset,
            Some(if call.is_root { F::one() } else { F::zero() }),
        )?;
        self.is_create.assign(
            region,
            offset,
            Some(if call.is_create { F::one() } else { F::zero() }),
        )?;
        self.is_success.assign(
            region,
            offset,
            Some(if call.is_success { F::one() } else { F::zero() }),
        )?;

        if !call.is_root {
            self.restore_context
                .assign(region, offset, block, call, step, 5)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::run_test_circuits};
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    #[test]
    fn test_return() {
        let bytecode = bytecode! {
            PUSH32(34234)
            PUSH32(32342) // i think there's a memory expansion issue when there this value is too large?
            RETURN
        };

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None
            ),
            Ok(())
        );
    }
}
