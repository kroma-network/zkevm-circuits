use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, CachedRegion, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct GasGadget<F> {
    same_context: SameContextGadget<F>,
    gas_left: RandomLinearCombination<F, N_BYTES_GAS>,
}

impl<F: Field> ExecutionGadget<F> for GasGadget<F> {
    const NAME: &'static str = "GAS";

    const EXECUTION_STATE: ExecutionState = ExecutionState::GAS;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // The gas passed to a transaction is a 64-bit number.
        let gas_left = cb.query_word_rlc();

        // The `gas_left` in the current state has to be deducted by the gas
        // used by the `GAS` opcode itself.
        cb.require_equal(
            "Constraint: gas left equal to stack value",
            from_bytes::expr(&gas_left.cells),
            cb.curr.state.gas_left.expr() - OpcodeId::GAS.constant_gas_cost().expr(),
        );

        // Construct the value and push it to stack.
        cb.stack_push(gas_left.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::GAS.constant_gas_cost().expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            gas_left,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        _block: &Block<F>,
        _transaction: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // The GAS opcode takes into account the reduction of gas available due
        // to the instruction itself.
        self.gas_left.assign(
            region,
            offset,
            Some(
                step.gas_left
                    .saturating_sub(OpcodeId::GAS.constant_gas_cost().as_u64())
                    .to_le_bytes(),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{address, bytecode, Word};
    #[cfg(feature = "kroma")]
    use mock::test_ctx::helpers::{setup_kroma_required_accounts, system_deposit_tx};
    use mock::{test_ctx::SimpleTestContext, tx_idx};

    fn test_ok() {
        let bytecode = bytecode! {
            GAS
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            SimpleTestContext::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn gas_gadget_simple() {
        test_ok();
    }

    #[test]
    fn gas_gadget_incorrect_deduction() {
        let bytecode = bytecode! {
            GAS
            STOP
        };

        // Create a custom tx setting Gas to
        let ctx = SimpleTestContext::new(
            None,
            |mut accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(bytecode);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .balance(Word::from(1u64 << 20));
                #[cfg(feature = "kroma")]
                setup_kroma_required_accounts(accs.as_mut_slice(), 2);
            },
            |mut txs, accs| {
                #[cfg(feature = "kroma")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .gas(Word::from(1_000_000u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::<7, 2>::new_from_test_ctx(ctx)
            .block_modifier(Box::new(|block| {
                // The above block has 2 steps (GAS and STOP). We forcefully assign a
                // wrong `gas_left` value for the second step, to assert that
                // the circuit verification fails for this scenario.
                assert_eq!(block.txs.len(), 2);
                // BeginTx, Gas, Stop, (FeeDistributionHook, ProposerRewardHook,)
                // EndTx, EndInnerBlock, EndBlock
                #[cfg(feature = "kroma")]
                let n_steps_in_tx = 7;
                // BeginTx, Gas, Stop, EndTx, EndInnerBlock, EndBlock
                #[cfg(not(feature = "kroma"))]
                let n_steps_in_tx = 5;
                assert_eq!(block.txs[tx_idx!(0)].steps.len(), n_steps_in_tx);
                block.txs[tx_idx!(0)].steps[2].gas_left -= 1;
            }))
            .evm_checks(Box::new(|prover, gate_rows, lookup_rows| {
                assert!(prover
                    .verify_at_rows_par(gate_rows.iter().cloned(), lookup_rows.iter().cloned())
                    .is_err())
            }))
            .run();

        // let mut builder =
        // BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder(); builder
        //     .handle_block(&block.eth_block, &block.geth_traces)
        //     .expect("could not handle block tx");
        // let mut block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

        // // The above block has 2 steps (GAS and STOP). We forcefully assign a
        // // wrong `gas_left` value for the second step, to assert that
        // // the circuit verification fails for this scenario.
        // assert_eq!(block.txs.len(), 1);
        // #[cfg(feature = "kanvas")]
        // // BeginTx, Gas, Stop, BaseFeeHook, RollupFeeHook, EndTx, EndInnerBlock,
        // // EndBlock
        // assert_eq!(block.txs[0].steps.len(), 7);
        // #[cfg(not(feature = "kanvas"))]
        // // BeginTx, Gas, Stop, EndTx, EndInnerBlock, EndBlock
        // assert_eq!(block.txs[0].steps.len(), 5);
        // block.txs[0].steps[2].gas_left -= 1;
        // assert!(run_test_circuit(block).is_err());
    }
}
