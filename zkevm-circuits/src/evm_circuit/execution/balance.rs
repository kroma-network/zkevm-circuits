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
    reversion_info: ReversionInfo<F>,
    tx_id: Cell<F>,
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
            reversion_info,
            tx_id,
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

        let (_, is_warm) = block.rws[step.rw_indices[4]].tx_access_list_value_pair();
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
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::run_test_circuits;
    use eth_types::geth_types::Account;
    use eth_types::{address, bytecode, Address, Bytecode, ToWord, Word, U256};
    use lazy_static::lazy_static;
    use mock::TestContext;

    lazy_static! {
        static ref TEST_ADDRESS: Address = address!("0xaabbccddee000000000000000000000000000000");
    }

    #[test]
    fn balance_gadget_non_existing_account() {
        test_root_ok(&None, false);
        test_internal_ok(0x20, 0x00, &None, false);
        test_internal_ok(0x1010, 0xff, &None, false);
    }

    #[test]
    fn balance_gadget_cold_account() {
        let account = Some(Account {
            address: *TEST_ADDRESS,
            balance: U256::from(900),
            ..Default::default()
        });

        test_root_ok(&account, false);
        test_internal_ok(0x20, 0x00, &account, false);
        test_internal_ok(0x1010, 0xff, &account, false);
    }

    #[test]
    fn balance_gadget_warm_account() {
        let account = Some(Account {
            address: *TEST_ADDRESS,
            balance: U256::from(900),
            ..Default::default()
        });

        test_root_ok(&account, true);
        test_internal_ok(0x20, 0x00, &account, true);
        test_internal_ok(0x1010, 0xff, &account, true);
    }

    fn test_root_ok(account: &Option<Account>, is_warm: bool) {
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);

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
            BALANCE
            STOP
        });

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(1_u64 << 20))
                    .code(code);
                accs[1].address(address);
                if let Some(account) = account {
                    accs[1].balance(account.balance);
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1_u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }

    fn test_internal_ok(
        call_data_offset: usize,
        call_data_length: usize,
        account: &Option<Account>,
        is_warm: bool,
    ) {
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let mut code_b = Bytecode::default();
        if is_warm {
            code_b.append(&bytecode! {
                PUSH20(address.to_word())
                BALANCE
                POP
            });
        }
        code_b.append(&bytecode! {
            PUSH20(address.to_word())
            BALANCE
            STOP
        });

        // code A calls code B.
        let pushdata = rand_bytes(8);
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<4, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2].address(address);
                if let Some(account) = account {
                    accs[2].balance(account.balance);
                }
                accs[3]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1_u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[3].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }
}
