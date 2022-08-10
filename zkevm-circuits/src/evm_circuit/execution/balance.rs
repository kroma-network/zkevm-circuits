use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_ACCOUNT_ADDRESS;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::SameContextGadget;
use crate::evm_circuit::util::constraint_builder::Transition::Delta;
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, ReversionInfo, StepStateTransition,
};
use crate::evm_circuit::util::{from_bytes, CachedRegion, Cell, RandomLinearCombination};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::table::{AccountFieldTag, CallContextFieldTag};
use crate::util::Expr;
use eth_types::evm_types::GasCost;
use eth_types::{Field, ToAddress, ToScalar, U256};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct BalanceGadget<F> {
    same_context: SameContextGadget<F>,
    address: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    is_warm: Cell<F>,
    balance: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for BalanceGadget<F> {
    const NAME: &'static str = "BALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BALANCE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let address = cb.query_rlc();
        cb.stack_pop(address.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info(None);
        let is_warm = cb.query_bool();

        cb.account_access_list_write(
            tx_id.expr(),
            from_bytes::expr(&address.cells),
            1.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        let balance = cb.query_cell();
        cb.account_read(
            from_bytes::expr(&address.cells),
            AccountFieldTag::Balance,
            balance.expr(),
        );

        cb.stack_push(balance.expr());

        let gas_cost = is_warm.expr() * GasCost::WARM_ACCESS.expr()
            + (1.expr() - is_warm.expr()) * GasCost::COLD_ACCOUNT_ACCESS.expr();

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-gas_cost),
            reversible_write_counter: Delta(1.expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address,
            tx_id,
            reversion_info,
            is_warm,
            balance,
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

        let mut address_bytes = block.rws[step.rw_indices[0]].stack_value().to_address().0;
        address_bytes.reverse();
        self.address.assign(region, offset, Some(address_bytes))?;

        self.tx_id
            .assign(region, offset, U256::from(tx.id).to_scalar())?;

        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;

        let is_warm = match GasCost::from(step.gas_cost) {
            GasCost::COLD_ACCOUNT_ACCESS => 0,
            GasCost::WARM_ACCESS => 1,
            _ => unreachable!(),
        };
        self.is_warm
            .assign(region, offset, Some(F::from(is_warm)))?;

        let balance = block.rws[step.rw_indices[5]]
            .table_assignment(block.randomness)
            .value;
        self.balance.assign(region, offset, Some(balance))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::witness::block_convert;
    use crate::test_util::{test_circuits_using_witness_block, BytecodeTestConfig};
    use bus_mapping::mock::BlockData;
    use eth_types::geth_types::{Account, GethData};
    use eth_types::{address, bytecode, Address, Bytecode, ToWord, Word, U256};
    use lazy_static::lazy_static;
    use mock::TestContext;

    lazy_static! {
        static ref ADDRESS: Address = address!("0xaabbccddee000000000000000000000000000000");
    }

    #[test]
    fn balance_gadget_of_non_existing_address() {
        test_ok(None, false);
    }

    #[test]
    fn balance_gadget_of_cold_address() {
        test_ok(
            Some(Account {
                address: *ADDRESS,
                balance: U256::from(900),
                ..Default::default()
            }),
            false,
        );
    }

    #[test]
    fn balance_gadget_of_warm_address() {
        test_ok(
            Some(Account {
                address: *ADDRESS,
                balance: U256::from(900),
                ..Default::default()
            }),
            true,
        );
    }

    fn test_ok(external_account: Option<Account>, is_warm: bool) {
        let address = external_account
            .as_ref()
            .map(|a| a.address)
            .unwrap_or(*ADDRESS);

        // Make the external account warm, if needed, by first getting its external code
        // hash.
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                PUSH20(address.to_word())
                BALANCE
                POP
            });
        }
        code.append(&bytecode! {
            PUSH20(address.to_word())
            #[start]
            BALANCE
            STOP
        });

        // Execute the bytecode and get trace
        let block: GethData = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(1u64 << 20))
                    .code(code);
                accs[1].address(address);
                if let Some(external_account) = external_account {
                    accs[1].balance(external_account.balance);
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .expect("could not handle block tx");

        test_circuits_using_witness_block(
            block_convert(&builder.block, &builder.code_db),
            BytecodeTestConfig::default(),
        )
        .unwrap();
    }
}
