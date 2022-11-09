use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE};
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::TransferGadget;
use crate::evm_circuit::util::constraint_builder::Transition::{Delta, To};
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, ReversionInfo, StepStateTransition,
};
use crate::evm_circuit::util::math_gadget::{
    generate_lagrange_base_polynomial, BatchedIsZeroGadget, ConstantDivisionGadget, IsEqualGadget,
    IsZeroGadget, MinMaxGadget,
};
use crate::evm_circuit::util::memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget};
use crate::evm_circuit::util::{from_bytes, select, sum, CachedRegion, Cell, Word};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::table::{AccountFieldTag, CallContextFieldTag};
use crate::util::Expr;
use bus_mapping::evm::OpcodeId;
use eth_types::evm_types::{GasCost, GAS_STIPEND_CALL_WITH_VALUE};
use eth_types::{Field, ToLittleEndian, ToScalar, U256};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Error, Expression};
use keccak256::EMPTY_HASH_LE;

/// Gadget for call related opcodes. It supports `OpcodeId::CALL`,
/// `OpcodeId::CALLCODE`, `OpcodeId::DELEGATECALL` and `OpcodeId::STATICCALL`.
#[derive(Clone, Debug)]
pub(crate) struct CallOpGadget<F> {
    opcode: Cell<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    current_address: Cell<F>,
    parent_address: Cell<F>,
    parent_value: Cell<F>,
    is_static: Cell<F>,
    depth: Cell<F>,
    gas: Word<F>,
    code_address: Word<F>,
    value: Word<F>,
    is_success: Cell<F>,
    gas_is_u64: IsZeroGadget<F>,
    is_warm: Cell<F>,
    is_warm_prev: Cell<F>,
    callee_reversion_info: ReversionInfo<F>,
    value_is_zero: IsZeroGadget<F>,
    cd_address: MemoryAddressGadget<F>,
    rd_address: MemoryAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 2, N_BYTES_MEMORY_WORD_SIZE>,
    transfer: TransferGadget<F>,
    callee_nonce: Cell<F>,
    callee_code_hash: Cell<F>,
    is_empty_nonce_and_balance: BatchedIsZeroGadget<F, 2>,
    is_empty_code_hash: IsEqualGadget<F>,
    one_64th_gas: ConstantDivisionGadget<F, N_BYTES_GAS>,
    capped_callee_gas_left: MinMaxGadget<F, N_BYTES_GAS>,
}

impl<F: Field> ExecutionGadget<F> for CallOpGadget<F> {
    const NAME: &'static str = "CALL_OP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALL_OP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());
        let is_call = is_opcode(&opcode, OpcodeId::CALL);
        let is_callcode = is_opcode(&opcode, OpcodeId::CALLCODE);
        let is_delegatecall = is_opcode(&opcode, OpcodeId::DELEGATECALL);
        let is_staticcall = is_opcode(&opcode, OpcodeId::STATICCALL);

        // We do the responsible opcode check explicitly here because we're not
        // using the `SameContextGadget` for `CALL`, `CALLCODE`, `DELEGATECALL`
        // or `STATICCALL`.
        cb.require_equal(
            "Opcode should be CALL, CALLCODE, DELEGATECALL or STATICCALL",
            is_call.expr() + is_callcode.expr() + is_delegatecall.expr() + is_staticcall.expr(),
            1.expr(),
        );

        let gas_word = cb.query_word();
        let code_address_word = cb.query_word();
        let value = cb.query_word();
        let cd_offset = cb.query_cell();
        let cd_length = cb.query_rlc();
        let rd_offset = cb.query_cell();
        let rd_length = cb.query_rlc();
        let is_success = cb.query_bool();

        // Use rw_counter of the step which triggers next call as its call_id.
        let callee_call_id = cb.curr.state.rw_counter.clone();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let [is_static, depth, current_address] = [
            CallContextFieldTag::IsStatic,
            CallContextFieldTag::Depth,
            CallContextFieldTag::CalleeAddress,
        ]
        .map(|field_tag| cb.call_context(None, field_tag));

        let [parent_address, parent_value] = cb.condition(is_delegatecall.expr(), |cb| {
            [
                CallContextFieldTag::CallerAddress,
                CallContextFieldTag::Value,
            ]
            .map(|field_tag| cb.call_context(None, field_tag))
        });

        cb.range_lookup(depth.expr(), 1024);

        // Lookup values from stack
        cb.stack_pop(gas_word.expr());
        cb.stack_pop(code_address_word.expr());

        // `CALL` opcode has an additional stack pop `value`.
        cb.condition(is_call.expr(), |cb| cb.stack_pop(value.expr()));

        [
            cd_offset.expr(),
            cd_length.expr(),
            rd_offset.expr(),
            rd_length.expr(),
        ]
        .map(|expression| cb.stack_pop(expression));
        cb.stack_push(is_success.expr());

        // Recomposition of random linear combination to integer
        let gas = from_bytes::expr(&gas_word.cells[..N_BYTES_GAS]);
        let gas_is_u64 = IsZeroGadget::construct(cb, sum::expr(&gas_word.cells[N_BYTES_GAS..]));
        let cd_address = MemoryAddressGadget::construct(cb, cd_offset, cd_length);
        let rd_address = MemoryAddressGadget::construct(cb, rd_offset, rd_length);
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_word_size.expr(),
            [cd_address.address(), rd_address.address()],
        );

        // `code_address` is poped from stack and used to check if it exists in
        // access list and get code hash. For opcode `CALLCODE`, both caller and
        // callee addresses are `current_address` (caller address). For opcode
        // `DELEGATECALL`, caller address is `parent_address` and callee address
        // is `current_address`. Otherwise caller address is `current_address`
        // and callee address is `code_address`.
        let code_address = from_bytes::expr(&code_address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);
        let caller_address = select::expr(
            is_delegatecall.expr(),
            parent_address.expr(),
            current_address.expr(),
        );
        let callee_address = select::expr(
            is_callcode.expr() + is_delegatecall.expr(),
            current_address.expr(),
            code_address.expr(),
        );

        // Add callee to access list
        let is_warm = cb.query_bool();
        let is_warm_prev = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            code_address.expr(),
            is_warm.expr(),
            is_warm_prev.expr(),
            Some(&mut reversion_info),
        );

        // Propagate rw_counter_end_of_reversion and is_persistent
        let mut callee_reversion_info = cb.reversion_info_write(Some(callee_call_id.expr()));
        cb.require_equal(
            "callee_is_persistent == is_persistent ⋅ is_success",
            callee_reversion_info.is_persistent(),
            reversion_info.is_persistent() * is_success.expr(),
        );
        cb.condition(is_success.expr() * (1.expr() - reversion_info.is_persistent()), |cb| {
            cb.require_equal(
                "callee_rw_counter_end_of_reversion == rw_counter_end_of_reversion - (reversible_write_counter + 1)",
                callee_reversion_info.rw_counter_end_of_reversion(),
                reversion_info.rw_counter_of_reversion(),
            );
        });

        let value_is_zero = IsZeroGadget::construct(cb, sum::expr(&value.cells));
        let has_value = 1.expr() - value_is_zero.expr();
        cb.condition(has_value.clone(), |cb| {
            cb.require_zero(
                "CALL with value must not be in static call stack",
                is_static.expr(),
            );
        });

        // Verify transfer
        let transfer = TransferGadget::construct(
            cb,
            caller_address.expr(),
            callee_address.expr(),
            value.clone(),
            &mut callee_reversion_info,
        );

        // Verify gas cost
        let callee_nonce = cb.query_cell();
        cb.account_read(
            callee_address.expr(),
            AccountFieldTag::Nonce,
            callee_nonce.expr(),
        );
        let callee_code_hash = cb.query_cell();
        cb.account_read(
            code_address,
            AccountFieldTag::CodeHash,
            callee_code_hash.expr(),
        );
        let is_empty_nonce_and_balance = BatchedIsZeroGadget::construct(
            cb,
            [
                callee_nonce.expr(),
                transfer.receiver().balance_prev().expr(),
            ],
        );
        let is_empty_code_hash = IsEqualGadget::construct(
            cb,
            callee_code_hash.expr(),
            Word::random_linear_combine_expr(
                (*EMPTY_HASH_LE).map(|byte| byte.expr()),
                cb.power_of_randomness(),
            ),
        );
        let is_empty_account = is_empty_nonce_and_balance.expr() * is_empty_code_hash.expr();
        // Sum up gas cost
        let gas_cost = select::expr(
            is_warm_prev.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        ) + has_value.clone()
            * (GasCost::CALL_WITH_VALUE.expr() + is_empty_account * GasCost::NEW_ACCOUNT.expr())
            + memory_expansion.gas_cost();

        // Apply EIP 150
        let gas_available = cb.curr.state.gas_left.expr() - gas_cost.clone();
        let one_64th_gas = ConstantDivisionGadget::construct(cb, gas_available.clone(), 64);
        let all_but_one_64th_gas = gas_available - one_64th_gas.quotient();
        let capped_callee_gas_left = MinMaxGadget::construct(cb, gas, all_but_one_64th_gas.clone());
        let callee_gas_left = select::expr(
            gas_is_u64.expr(),
            capped_callee_gas_left.min(),
            all_but_one_64th_gas,
        );

        // TODO: Handle precompiled

        let stack_pointer_delta =
            select::expr(is_call.expr() + is_callcode.expr(), 6.expr(), 5.expr());
        cb.condition(is_empty_code_hash.expr(), |cb| {
            // Save caller's call state
            for field_tag in [
                CallContextFieldTag::LastCalleeId,
                CallContextFieldTag::LastCalleeReturnDataOffset,
                CallContextFieldTag::LastCalleeReturnDataLength,
            ] {
                cb.call_context_lookup(true.expr(), None, field_tag, 0.expr());
            }

            // Both `CALL` and `CALLCODE` have an extra stack pop `value`, and
            // opcode `DELEGATECALL` has two extra call context lookups - parent
            // caller address and value.
            let rw_counter_delta =
                23.expr() + is_call.expr() + is_callcode.expr() + is_delegatecall.expr() * 2.expr();
            cb.require_step_state_transition(StepStateTransition {
                rw_counter: Delta(rw_counter_delta),
                program_counter: Delta(1.expr()),
                stack_pointer: Delta(stack_pointer_delta.expr()),
                gas_left: Delta(
                    has_value.clone() * GAS_STIPEND_CALL_WITH_VALUE.expr() - gas_cost.clone(),
                ),
                memory_word_size: To(memory_expansion.next_memory_word_size()),
                reversible_write_counter: Delta(3.expr()),
                ..StepStateTransition::default()
            });
        });

        cb.condition(1.expr() - is_empty_code_hash.expr(), |cb| {
            // Save caller's call state
            for (field_tag, value) in [
                (
                    CallContextFieldTag::ProgramCounter,
                    cb.curr.state.program_counter.expr() + 1.expr(),
                ),
                (
                    CallContextFieldTag::StackPointer,
                    cb.curr.state.stack_pointer.expr() + stack_pointer_delta,
                ),
                (
                    CallContextFieldTag::GasLeft,
                    cb.curr.state.gas_left.expr() - gas_cost - callee_gas_left.clone(),
                ),
                (
                    CallContextFieldTag::MemorySize,
                    memory_expansion.next_memory_word_size(),
                ),
                (
                    CallContextFieldTag::ReversibleWriteCounter,
                    cb.curr.state.reversible_write_counter.expr() + 1.expr(),
                ),
            ] {
                cb.call_context_lookup(true.expr(), None, field_tag, value);
            }

            // Setup next call's context.
            for (field_tag, value) in [
                (CallContextFieldTag::CallerId, cb.curr.state.call_id.expr()),
                (CallContextFieldTag::TxId, tx_id.expr()),
                (CallContextFieldTag::Depth, depth.expr() + 1.expr()),
                (CallContextFieldTag::CallerAddress, caller_address),
                (CallContextFieldTag::CalleeAddress, callee_address),
                (CallContextFieldTag::CallDataOffset, cd_address.offset()),
                (CallContextFieldTag::CallDataLength, cd_address.length()),
                (CallContextFieldTag::ReturnDataOffset, rd_address.offset()),
                (CallContextFieldTag::ReturnDataLength, rd_address.length()),
                (
                    CallContextFieldTag::Value,
                    select::expr(is_delegatecall.expr(), parent_value.expr(), value.expr()),
                ),
                (CallContextFieldTag::IsSuccess, is_success.expr()),
                (CallContextFieldTag::IsStatic, is_staticcall),
                (CallContextFieldTag::LastCalleeId, 0.expr()),
                (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
                (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
                (CallContextFieldTag::IsRoot, 0.expr()),
                (CallContextFieldTag::IsCreate, 0.expr()),
                (CallContextFieldTag::CodeHash, callee_code_hash.expr()),
            ] {
                cb.call_context_lookup(true.expr(), Some(callee_call_id.expr()), field_tag, value);
            }

            // Give gas stipend if value is not zero
            let callee_gas_left = callee_gas_left + has_value * GAS_STIPEND_CALL_WITH_VALUE.expr();

            // Both `CALL` and `CALLCODE` have an extra stack pop `value`, and
            // opcode `DELEGATECALL` has two extra call context lookups - parent
            // caller address and value.
            let rw_counter_delta = 43.expr() + is_call + is_callcode + is_delegatecall * 2.expr();
            cb.require_step_state_transition(StepStateTransition {
                rw_counter: Delta(rw_counter_delta),
                call_id: To(callee_call_id.expr()),
                is_root: To(false.expr()),
                is_create: To(false.expr()),
                code_hash: To(callee_code_hash.expr()),
                gas_left: To(callee_gas_left),
                reversible_write_counter: To(2.expr()),
                ..StepStateTransition::new_context()
            });
        });

        Self {
            opcode,
            tx_id,
            reversion_info,
            current_address,
            parent_address,
            parent_value,
            is_static,
            depth,
            gas: gas_word,
            code_address: code_address_word,
            value,
            is_success,
            gas_is_u64,
            is_warm,
            is_warm_prev,
            callee_reversion_info,
            value_is_zero,
            cd_address,
            rd_address,
            memory_expansion,
            transfer,
            callee_nonce,
            callee_code_hash,
            is_empty_nonce_and_balance,
            is_empty_code_hash,
            one_64th_gas,
            capped_callee_gas_left,
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
        let opcode = step.opcode.unwrap();
        let is_call_or_callcode = opcode == OpcodeId::CALL || opcode == OpcodeId::CALLCODE;
        let is_delegatecall = opcode == OpcodeId::DELEGATECALL;
        let [tx_id, is_static, depth, current_address] = [
            step.rw_indices[0],
            step.rw_indices[3],
            step.rw_indices[4],
            step.rw_indices[5],
        ]
        .map(|idx| block.rws[idx].call_context_value());
        // This offset is used to change the index offset of `step.rw_indices`.
        // Since both `CALL` and `CALLCODE `have an extra stack pop `value`, and
        // opcode `DELEGATECALL` has two extra call context lookups - parent
        // caller address and value.
        let mut rw_offset = 0;
        let [parent_address, parent_value] = if is_delegatecall {
            rw_offset += 2;
            [step.rw_indices[6], step.rw_indices[7]].map(|idx| block.rws[idx].call_context_value())
        } else {
            [U256::from(0), U256::from(0)]
        };
        let [gas, code_address] = [
            step.rw_indices[6 + rw_offset],
            step.rw_indices[7 + rw_offset],
        ]
        .map(|idx| block.rws[idx].stack_value());
        let value = if is_call_or_callcode {
            rw_offset += 1;
            block.rws[step.rw_indices[7 + rw_offset]].stack_value()
        } else {
            U256::from(0)
        };
        let [cd_offset, cd_length, rd_offset, rd_length, is_success] = [
            step.rw_indices[8 + rw_offset],
            step.rw_indices[9 + rw_offset],
            step.rw_indices[10 + rw_offset],
            step.rw_indices[11 + rw_offset],
            step.rw_indices[12 + rw_offset],
        ]
        .map(|idx| block.rws[idx].stack_value());
        let (is_warm, is_warm_prev) =
            block.rws[step.rw_indices[13 + rw_offset]].tx_access_list_value_pair();
        let [callee_rw_counter_end_of_reversion, callee_is_persistent] = [
            step.rw_indices[14 + rw_offset],
            step.rw_indices[15 + rw_offset],
        ]
        .map(|idx| block.rws[idx].call_context_value());
        let [caller_balance_pair, callee_balance_pair, (callee_nonce, _), (callee_code_hash, _)] =
            [
                step.rw_indices[16 + rw_offset],
                step.rw_indices[17 + rw_offset],
                step.rw_indices[18 + rw_offset],
                step.rw_indices[19 + rw_offset],
            ]
            .map(|idx| block.rws[idx].account_value_pair());
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.tx_id
            .assign(region, offset, Value::known(F::from(tx_id.low_u64())))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.current_address.assign(
            region,
            offset,
            Value::known(
                current_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.parent_address.assign(
            region,
            offset,
            Value::known(
                parent_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.parent_value.assign(
            region,
            offset,
            Value::known(
                parent_value
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;
        self.is_static
            .assign(region, offset, Value::known(F::from(is_static.low_u64())))?;
        self.depth
            .assign(region, offset, Value::known(F::from(depth.low_u64())))?;
        self.gas.assign(region, offset, Some(gas.to_le_bytes()))?;
        self.code_address
            .assign(region, offset, Some(code_address.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        self.is_success
            .assign(region, offset, Value::known(F::from(is_success.low_u64())))?;
        self.gas_is_u64.assign(
            region,
            offset,
            sum::value(&gas.to_le_bytes()[N_BYTES_GAS..]),
        )?;
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;
        self.is_warm_prev
            .assign(region, offset, Value::known(F::from(is_warm_prev as u64)))?;
        self.callee_reversion_info.assign(
            region,
            offset,
            callee_rw_counter_end_of_reversion.low_u64() as usize,
            callee_is_persistent.low_u64() != 0,
        )?;
        self.value_is_zero
            .assign(region, offset, sum::value(&value.to_le_bytes()))?;
        let cd_address =
            self.cd_address
                .assign(region, offset, cd_offset, cd_length, block.randomness)?;
        let rd_address =
            self.rd_address
                .assign(region, offset, rd_offset, rd_length, block.randomness)?;
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [cd_address, rd_address],
        )?;
        self.transfer.assign(
            region,
            offset,
            caller_balance_pair,
            callee_balance_pair,
            value,
        )?;
        self.callee_nonce.assign(
            region,
            offset,
            Value::known(
                callee_nonce
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;
        self.callee_code_hash.assign(
            region,
            offset,
            Value::known(Word::random_linear_combine(
                callee_code_hash.to_le_bytes(),
                block.randomness,
            )),
        )?;
        let is_empty_nonce_and_balance = self.is_empty_nonce_and_balance.assign(
            region,
            offset,
            [
                F::from(callee_nonce.low_u64()),
                Word::random_linear_combine(callee_balance_pair.1.to_le_bytes(), block.randomness),
            ],
        )?;
        let is_empty_code_hash = self.is_empty_code_hash.assign(
            region,
            offset,
            Word::random_linear_combine(callee_code_hash.to_le_bytes(), block.randomness),
            Word::random_linear_combine(*EMPTY_HASH_LE, block.randomness),
        )?;
        let is_empty_account = is_empty_nonce_and_balance * is_empty_code_hash;
        let has_value = !value.is_zero();
        let gas_cost = if is_warm_prev {
            GasCost::WARM_ACCESS.as_u64()
        } else {
            GasCost::COLD_ACCOUNT_ACCESS.as_u64()
        } + if has_value {
            GasCost::CALL_WITH_VALUE.as_u64()
                + if is_empty_account == F::one() {
                    GasCost::NEW_ACCOUNT.as_u64()
                } else {
                    0
                }
        } else {
            0
        } + memory_expansion_gas_cost;
        let gas_available = step.gas_left - gas_cost;
        self.one_64th_gas
            .assign(region, offset, gas_available as u128)?;
        self.capped_callee_gas_left.assign(
            region,
            offset,
            F::from(gas.low_u64()),
            F::from(gas_available - gas_available / 64),
        )?;
        Ok(())
    }
}

#[inline]
fn is_opcode<F: Field>(opcode: &Cell<F>, opcode_id: OpcodeId) -> Expression<F> {
    generate_lagrange_base_polynomial(
        opcode,
        opcode_id.as_u8() as usize,
        [OpcodeId::CALL, OpcodeId::DELEGATECALL, OpcodeId::STATICCALL]
            .into_iter()
            .map(|op_id| op_id.as_u8() as usize),
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::evm_circuit::test::{
        run_test_circuit_geth_data, run_test_circuit_geth_data_default,
    };
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{address, bytecode, Address, ToWord, Word};
    use eth_types::{
        bytecode::Bytecode,
        evm_types::OpcodeId,
        geth_types::{Account, GethData},
    };
    use halo2_proofs::halo2curves::bn256::Fr;
    use itertools::Itertools;
    use mock::TestContext;
    use std::default::Default;

    const TEST_CALL_OPCODES: &[OpcodeId] = &[
        OpcodeId::CALL,
        OpcodeId::CALLCODE,
        OpcodeId::DELEGATECALL,
        OpcodeId::STATICCALL,
    ];

    #[test]
    fn callop_insufficient_balance() {
        let stacks = [Stack {
            // this value is bigger than caller's balance
            value: Word::from(11).pow(18.into()),
            ..Default::default()
        }];
        let callees = [callee(bytecode! {}), callee(bytecode! { STOP })];
        for ((opcode, stack), callee) in TEST_CALL_OPCODES
            .iter()
            .cartesian_product(stacks.into_iter())
            .cartesian_product(callees.into_iter())
        {
            test_ok(caller_for_insufficient_balance(opcode, stack), callee);
        }
    }

    #[test]
    fn callop_nested() {
        for opcode in TEST_CALL_OPCODES {
            test_nested(opcode);
        }
    }

    #[test]
    fn callop_oog() {
        let stacks = [
            // With gas and memory expansion
            Stack {
                gas: 100,
                cd_offset: 64,
                cd_length: 320,
                rd_offset: 0,
                rd_length: 32,
                ..Default::default()
            },
        ];

        let bytecode = bytecode! {
            PUSH32(Word::from(0))
            PUSH32(Word::from(0))
            STOP
        };
        let callees = [callee(bytecode)];
        for ((opcode, stack), callee) in TEST_CALL_OPCODES
            .iter()
            .cartesian_product(stacks.into_iter())
            .cartesian_product(callees.into_iter())
        {
            test_oog(caller(opcode, stack, true), callee);
        }
    }

    #[test]
    fn callop_recursive() {
        for opcode in TEST_CALL_OPCODES {
            test_recursive(opcode);
        }
    }

    #[test]
    fn callop_simple() {
        let stacks = [
            // With nothing
            Stack::default(),
            // With value
            Stack {
                value: Word::from(10).pow(18.into()),
                ..Default::default()
            },
            // With gas
            Stack {
                gas: 100,
                ..Default::default()
            },
            Stack {
                gas: 100000,
                ..Default::default()
            },
            // With memory expansion
            Stack {
                cd_offset: 64,
                cd_length: 320,
                rd_offset: 0,
                rd_length: 32,
                ..Default::default()
            },
            Stack {
                cd_offset: 0,
                cd_length: 32,
                rd_offset: 64,
                rd_length: 320,
                ..Default::default()
            },
            Stack {
                cd_offset: 0xFFFFFF,
                cd_length: 0,
                rd_offset: 0xFFFFFF,
                rd_length: 0,
                ..Default::default()
            },
        ];
        let callees = [callee(bytecode! {}), callee(bytecode! { STOP })];
        for ((opcode, stack), callee) in TEST_CALL_OPCODES
            .iter()
            .cartesian_product(stacks.into_iter())
            .cartesian_product(callees.into_iter())
        {
            test_ok(caller(opcode, stack, true), callee);
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Stack {
        gas: u64,
        value: Word,
        cd_offset: u64,
        cd_length: u64,
        rd_offset: u64,
        rd_length: u64,
    }

    fn callee(code: Bytecode) -> Account {
        let code = code.to_vec();
        let is_empty = code.is_empty();
        Account {
            address: Address::repeat_byte(0xff),
            code: code.into(),
            nonce: if is_empty { 0 } else { 1 }.into(),
            balance: if is_empty { 0 } else { 0xdeadbeefu64 }.into(),
            ..Default::default()
        }
    }

    fn caller(opcode: &OpcodeId, stack: Stack, caller_is_success: bool) -> Account {
        let is_call = opcode == &OpcodeId::CALL;
        let terminator = if caller_is_success {
            OpcodeId::RETURN
        } else {
            OpcodeId::REVERT
        };

        // Call twice for testing both cold and warm access
        let mut bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
        };
        if is_call {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(*opcode)
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
        });
        if is_call {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(*opcode)
            PUSH1(0)
            PUSH1(0)
            .write_op(terminator)
        });

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(20.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
    }

    fn caller_for_insufficient_balance(opcode: &OpcodeId, stack: Stack) -> Account {
        let is_call = opcode == &OpcodeId::CALL;
        let terminator = OpcodeId::STOP;

        let mut bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
        };
        if is_call {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(*opcode)
            .write_op(terminator)
        });

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(18.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
    }

    fn test_nested(opcode: &OpcodeId) {
        let callers = [
            caller(
                opcode,
                Stack {
                    gas: 100000,
                    ..Default::default()
                },
                true,
            ),
            caller(
                opcode,
                Stack {
                    gas: 100000,
                    ..Default::default()
                },
                false,
            ),
        ];
        let callees = [
            // Success
            callee(bytecode! { PUSH1(0) PUSH1(0) RETURN }),
            // Failure
            callee(bytecode! { PUSH1(0) PUSH1(0) REVERT }),
        ];

        for (caller, callee) in callers.into_iter().cartesian_product(callees.into_iter()) {
            test_ok(caller, callee);
        }
    }

    fn test_ok(caller: Account, callee: Account) {
        let block: GethData = TestContext::<3, 1>::new(
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
                    .gas(100000.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        assert_eq!(
            run_test_circuit_geth_data::<Fr>(
                block,
                CircuitsParams {
                    max_rws: 4500,
                    ..Default::default()
                }
            ),
            Ok(())
        );
    }

    fn test_oog(caller: Account, callee: Account) {
        let block: GethData = TestContext::<3, 1>::new(
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
                    .gas(21100.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        assert_eq!(run_test_circuit_geth_data_default::<Fr>(block), Ok(()));
    }

    fn test_recursive(opcode: &OpcodeId) {
        let is_call = opcode == &OpcodeId::CALL;
        let mut caller_bytecode = bytecode! {
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
        };
        if is_call {
            caller_bytecode.push(1, U256::from(0));
        }
        caller_bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH2(if is_call {10000} else {10032})
            .write_op(*opcode)
            STOP
        });
        // The following bytecode calls itself recursively if gas_left is greater than
        // 100, and halts with REVERT if gas_left is odd, otherwise just halts
        // with STOP.
        let mut callee_bytecode = bytecode! {
            GAS
            PUSH1(100)
            GT
            PUSH1(if is_call {43} else {41}) // jump dest
            JUMPI

            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
        };

        if is_call {
            callee_bytecode.push(1, U256::from(0));
        }

        callee_bytecode.append(&bytecode! {
            PUSH20(Address::repeat_byte(0xff).to_word())
            PUSH1(if is_call {132} else {129}) // gas
            GAS
            SUB
            .write_op(*opcode)

            JUMPDEST // 41 for static_call, 43 for call
            GAS
            PUSH1(1)
            AND
            PUSH1(if is_call {56} else {54})
            JUMPI

            PUSH1(0)
            PUSH1(0)
            REVERT

            // 56 or 54 for call or static_call
            JUMPDEST
            STOP
        });
        test_ok(
            Account {
                address: Address::repeat_byte(0xfe),
                balance: Word::from(10).pow(20.into()),
                code: caller_bytecode.into(),
                ..Default::default()
            },
            callee(callee_bytecode),
        );
    }
}
