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
use eth_types::{Field, ToLittleEndian, ToScalar};
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

        let length = cb.query_word();
        let offset = cb.query_word();
        cb.stack_pop(length.expr());
        cb.stack_pop(offset.expr());

        let is_root = cb.call_context(None, CallContextFieldTag::IsRoot);
        let is_create = cb.call_context(None, CallContextFieldTag::IsCreate);
        let is_success = cb.call_context(None, CallContextFieldTag::IsSuccess);

        cb.require_equal(
            "Opcode is RETURN if is_success, REVERT otherwise",
            opcode.expr(),
            is_success.expr() * OpcodeId::RETURN.expr()
                + not::expr(is_success.expr()) * OpcodeId::REVERT.expr(),
        );

        cb.condition(is_root.expr(), |cb| {
            cb.require_next_state(ExecutionState::EndTx);
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

        for (cell, value) in [
            (&self.is_root, call.is_root),
            (&self.is_create, call.is_create),
            (&self.is_success, call.is_success),
        ] {
            cell.assign(region, offset, value.to_scalar())?;
        }

        if !call.is_root {
            self.restore_context
                .assign(region, offset, block, call, step, 5)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        evm_circuit::{test::run_test_circuit_incomplete_fixed_table, witness::block_convert},
        test_util::run_test_circuits,
    };
    use eth_types::{address, bytecode, geth_types::Account, Address, ToWord, Word};
    use mock::TestContext;

    #[test]
    fn test_return() {
        let bytecode = bytecode! {
            PUSH32(34234)
            PUSH32(32342)
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

    // TODO: be sure to add tests that test offset = 0
    // root return with insufficient gas for memory expansion.

    #[test]
    fn test_return_nonroot() {
        let callee_bytecode = bytecode! {
            PUSH32(Word::MAX)
            PUSH1(Word::from(102u64))
            MSTORE
            PUSH1(Word::from(10)) // length!?!?
            PUSH2(Word::from(2)) // offset!?!?!
            RETURN
        };

        let callee = Account {
            address: Address::repeat_byte(0xff),
            code: callee_bytecode.to_vec().into(),
            nonce: Word::one(),
            balance: 0xdeadbeefu64.into(),
            ..Default::default()
        };

        let caller_bytecode = bytecode! {
            PUSH32(Word::from(10)) // call_return_data_length
            PUSH32(Word::from(10)) // call_return_data_offset
            PUSH32(Word::from(14u64))
            PUSH32(Word::from(10u64))
            PUSH32(Word::from(4u64)) // value
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(40000u64)) // gas
            CALL
            STOP
        };

        let caller = Account {
            address: Address::repeat_byte(0x34),
            code: caller_bytecode.to_vec().into(),
            nonce: Word::one(),
            balance: 0xdeadbeefu64.into(),
            ..Default::default()
        };

        let block = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(10u64.pow(19)));
                accs[1]
                    .address(caller.address)
                    .code(caller.code)
                    .nonce(caller.nonce)
                    .balance(caller.balance);
                accs[2]
                    .address(callee.address)
                    .code(callee.code)
                    .nonce(callee.nonce)
                    .balance(callee.balance);
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(accs[1].address)
                    .gas(100000u64.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();
        let block_data = bus_mapping::mock::BlockData::new_from_geth_data(block.into());
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&block_data.eth_block, &block_data.geth_traces)
            .unwrap();

        assert_eq!(
            run_test_circuit_incomplete_fixed_table(block_convert(
                &builder.block,
                &builder.code_db
            )),
            Ok(())
        );
    }
}
