use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            and,
            common_gadget::{TransferWithGasFeeGadget, UpdateBalanceGadget},
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            is_precompiled,
            math_gadget::{
                ContractCreateGadget, IsEqualGadget, IsZeroGadget, LtGadget, MulWordByU64Gadget,
                RangeCheckGadget,
            },
            CachedRegion, Cell, StepRws, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag, TxFieldTag as TxContextFieldTag},
};
use eth_types::{
    evm_types::rwc_util::BEGIN_TX_MINT_RWC_OFFSET, geth_types::DEPOSIT_TX_TYPE, Address, Field,
    ToLittleEndian, ToScalar,
};
use ethers_core::utils::{get_contract_address, keccak256, rlp::RlpStream};
#[cfg(feature = "reject-eip2718")]
use gadgets::util::select;
use gadgets::util::{expr_from_bytes, not, or, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct BeginDepositTxGadget<F> {
    tx_id: Cell<F>,
    tx_type: Cell<F>,
    tx_nonce: Cell<F>,
    tx_gas: Cell<F>,
    tx_gas_price: Word<F>,
    mint: UpdateBalanceGadget<F, 2, true>,
    mul_gas_fee_by_gas: MulWordByU64Gadget<F>,
    tx_caller_address: Cell<F>,
    tx_caller_address_is_zero: IsZeroGadget<F>,
    tx_callee_address: Cell<F>,
    tx_callee_address_is_zero: IsZeroGadget<F>,
    call_callee_address: Cell<F>,
    tx_is_create: Cell<F>,
    tx_value: Word<F>,
    tx_mint: Word<F>,
    tx_call_data_length: Cell<F>,
    tx_call_data_gas_cost: Cell<F>,
    reversion_info: ReversionInfo<F>,
    intrinsic_gas_cost: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, N_BYTES_GAS>,
    transfer_with_gas_fee: TransferWithGasFeeGadget<F>,
    phase2_code_hash: Cell<F>,
    is_empty_code_hash: IsEqualGadget<F>,
    is_precompile_lt: LtGadget<F, N_BYTES_ACCOUNT_ADDRESS>,
    /// Keccak256(RLP([tx_caller_address, tx_nonce]))
    caller_nonce_hash_bytes: [Cell<F>; N_BYTES_WORD],
    /// RLP gadget for CREATE address.
    create: ContractCreateGadget<F, false>,
    callee_not_exists: IsZeroGadget<F>,
    is_caller_callee_equal: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for BeginDepositTxGadget<F> {
    const NAME: &'static str = "BeginDepositTxGadget";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BeginDepositTx;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id = cb.curr.state.rw_counter.clone();

        let tx_id = cb.query_cell();
        cb.call_context_lookup(
            1.expr(),
            Some(call_id.expr()),
            CallContextFieldTag::TxId,
            tx_id.expr(),
        ); // rwc_delta += 1
        let mut reversion_info = cb.reversion_info_write(None); // rwc_delta += 2
        let is_persistent = reversion_info.is_persistent();
        cb.call_context_lookup(
            1.expr(),
            Some(call_id.expr()),
            CallContextFieldTag::IsSuccess,
            is_persistent.expr(),
        ); // rwc_delta += 1

        let [tx_type, tx_nonce, tx_gas, tx_caller_address, tx_callee_address, tx_is_create, tx_call_data_length, tx_call_data_gas_cost] =
            [
                TxContextFieldTag::Type,
                TxContextFieldTag::Nonce,
                TxContextFieldTag::Gas,
                TxContextFieldTag::CallerAddress,
                TxContextFieldTag::CalleeAddress,
                TxContextFieldTag::IsCreate,
                TxContextFieldTag::CallDataLength,
                TxContextFieldTag::CallDataGasCost,
            ]
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));

        cb.require_equal(
            "In BeginDepositTx, tx.type == 126",
            tx_type.expr(),
            DEPOSIT_TX_TYPE.expr(),
        );

        let tx_caller_address_is_zero = IsZeroGadget::construct(cb, tx_caller_address.expr());
        cb.require_equal(
            "CallerAddress != 0 (not a padding tx)",
            tx_caller_address_is_zero.expr(),
            false.expr(),
        );
        let tx_callee_address_is_zero = IsZeroGadget::construct(cb, tx_callee_address.expr());
        cb.condition(tx_is_create.expr(), |cb| {
            cb.require_equal(
                "Contract creation tx expects callee address to be zero",
                tx_callee_address_is_zero.expr(),
                true.expr(),
            )
        });
        let [tx_gas_price, tx_value] = [TxContextFieldTag::GasPrice, TxContextFieldTag::Value]
            .map(|field_tag| cb.tx_context_as_word(tx_id.expr(), field_tag, None));

        let call_callee_address = cb.query_cell();
        cb.condition(not::expr(tx_is_create.expr()), |cb| {
            cb.require_equal(
                "Tx to non-zero address",
                tx_callee_address.expr(),
                call_callee_address.expr(),
            );
        });

        // Add first BeginDepositTx step constraint to have tx_id == 1
        cb.step_first(|cb| {
            cb.require_equal("tx_id is initialized to be 1", tx_id.expr(), 1.expr());
        });

        // NOTE(luke): handle mint
        let tx_mint = cb.tx_context_as_word(tx_id.expr(), TxContextFieldTag::Mint, None);
        let mint = UpdateBalanceGadget::construct(
            cb,
            tx_caller_address.expr(),
            vec![tx_mint.clone()],
            None,
            Some(1.expr()),
        ); // rwc_delta += 1

        // Increase caller's nonce.
        // (tx caller's nonce always increases even when tx ends with error)
        cb.account_write(
            tx_caller_address.expr(),
            AccountFieldTag::Nonce,
            tx_nonce.expr() + 1.expr(),
            tx_nonce.expr(),
            None,
        ); // rwc_delta += 1

        // TODO: Implement EIP 1559 (currently it only supports legacy
        // transaction format)
        // Calculate transaction gas fee
        let mul_gas_fee_by_gas =
            MulWordByU64Gadget::construct(cb, tx_gas_price.clone(), tx_gas.expr());

        // TODO: Take gas cost of access list (EIP 2930) into consideration.
        // Use intrinsic gas
        let intrinsic_gas_cost = cb.query_cell();
        #[cfg(feature = "reject-eip2718")]
        cb.require_equal(
            "calculate intrinsic gas cost",
            intrinsic_gas_cost.expr(),
            select::expr(
                tx_is_create.expr(),
                eth_types::evm_types::GasCost::CREATION_TX.expr(),
                eth_types::evm_types::GasCost::TX.expr(),
            ) + tx_call_data_gas_cost.expr(),
        );
        // Check gas_left is sufficient
        let gas_left = tx_gas.expr() - intrinsic_gas_cost.expr();
        let sufficient_gas_left = RangeCheckGadget::construct(cb, gas_left.clone());

        // Prepare access list of caller and callee
        cb.account_access_list_write(
            tx_id.expr(),
            tx_caller_address.expr(),
            1.expr(),
            0.expr(),
            None,
        ); // rwc_delta += 1
        let is_caller_callee_equal = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            call_callee_address.expr(),
            1.expr(),
            // No extra constraint being used here.
            // Correctness will be enforced in build_tx_access_list_account_constraints
            is_caller_callee_equal.expr(),
            None,
        ); // rwc_delta += 1

        // Read code_hash of callee
        let phase2_code_hash = cb.query_cell_phase2();
        let is_empty_code_hash =
            IsEqualGadget::construct(cb, phase2_code_hash.expr(), cb.empty_code_hash_rlc());
        let callee_not_exists = IsZeroGadget::construct(cb, phase2_code_hash.expr());
        // no_callee_code is true when the account exists and has empty
        // code hash, or when the account doesn't exist (which we encode with
        // code_hash = 0).
        let no_callee_code = is_empty_code_hash.expr() + callee_not_exists.expr();

        // a valid precompile address is: 1 <= addr <= 9 (addr != 0 && addr < 0xA)
        let is_precompile_lt = LtGadget::construct(cb, tx_callee_address.expr(), 0xA.expr());
        let is_precompile = and::expr([
            not::expr(tx_callee_address_is_zero.expr()),
            is_precompile_lt.expr(),
        ]);
        cb.condition(
            and::expr([
                not::expr(tx_is_create.expr()),
                not::expr(is_precompile.expr()),
            ]),
            |cb| {
                cb.account_read(
                    call_callee_address.expr(),
                    AccountFieldTag::CodeHash,
                    phase2_code_hash.expr(),
                ); // rwc_delta += 1
            },
        );

        // Transfer value from caller to callee, creating account if necessary.
        let transfer_with_gas_fee = TransferWithGasFeeGadget::construct(
            cb,
            tx_caller_address.expr(),
            call_callee_address.expr(),
            or::expr([not::expr(callee_not_exists.expr()), is_precompile.expr()]),
            tx_is_create.expr(),
            tx_value.clone(),
            mul_gas_fee_by_gas.product().clone(),
            &mut reversion_info,
        );

        let caller_nonce_hash_bytes = array_init::array_init(|_| cb.query_byte());
        let create = ContractCreateGadget::construct(cb);
        cb.require_equal(
            "tx caller address equivalence",
            tx_caller_address.expr(),
            create.caller_address(),
        );
        cb.condition(tx_is_create.expr(), |cb| {
            cb.require_equal(
                "call callee address equivalence",
                call_callee_address.expr(),
                expr_from_bytes(&caller_nonce_hash_bytes[0..N_BYTES_ACCOUNT_ADDRESS]),
            );
        });
        cb.require_equal(
            "tx nonce equivalence",
            tx_nonce.expr(),
            create.caller_nonce(),
        );
        cb.condition(not::expr(no_callee_code.expr()), |cb| {
            cb.require_equal(
                "code hash equivalence",
                cb.curr.state.code_hash.expr(),
                phase2_code_hash.expr(),
            );
        });

        // 1. Handle contract creation transaction.
        cb.condition(tx_is_create.expr(), |cb| {
            let output_rlc = cb.word_rlc::<N_BYTES_WORD>(
                caller_nonce_hash_bytes
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            );
            cb.keccak_table_lookup(create.input_rlc(cb), create.input_length(), output_rlc);

            cb.account_write(
                call_callee_address.expr(),
                AccountFieldTag::Nonce,
                1.expr(),
                0.expr(),
                Some(&mut reversion_info),
            );
            for (field_tag, value) in [
                (CallContextFieldTag::Depth, 1.expr()),
                (CallContextFieldTag::CallerAddress, tx_caller_address.expr()),
                (
                    CallContextFieldTag::CalleeAddress,
                    call_callee_address.expr(),
                ),
                (CallContextFieldTag::CallDataOffset, 0.expr()),
                (
                    CallContextFieldTag::CallDataLength,
                    tx_call_data_length.expr(),
                ),
                (CallContextFieldTag::Value, tx_value.expr()),
                (CallContextFieldTag::IsStatic, 0.expr()),
                (CallContextFieldTag::LastCalleeId, 0.expr()),
                (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
                (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
                (CallContextFieldTag::IsRoot, 1.expr()),
                (CallContextFieldTag::IsCreate, 1.expr()),
                (
                    CallContextFieldTag::CodeHash,
                    cb.curr.state.code_hash.expr(),
                ),
            ] {
                cb.call_context_lookup(true.expr(), Some(call_id.expr()), field_tag, value);
            }

            cb.require_step_state_transition(StepStateTransition {
                // 22 + TransferWithGasFeeGadget associated reads and writes:
                //   - Write CallContext TxId
                //   - Write CallContext RwCounterEndOfReversion
                //   - Write CallContext IsPersistent
                //   - Write CallContext IsSuccess
                //   - Write Account Balance (handle mint)
                //   - Write Account Nonce
                //   - Write TxAccessListAccount
                //   - Write TxAccessListAccount
                //   - a TransferWithGasFeeGadget
                //   - Write Account (Callee) Nonce (Reversible)
                //   - Write CallContext Depth
                //   - Write CallContext CallerAddress
                //   - Write CallContext CalleeAddress
                //   - Write CallContext CallDataOffset
                //   - Write CallContext CallDataLength
                //   - Write CallContext Value
                //   - Write CallContext IsStatic
                //   - Write CallContext LastCalleeId
                //   - Write CallContext LastCalleeReturnDataOffset
                //   - Write CallContext LastCalleeReturnDataLength
                //   - Write CallContext IsRoot
                //   - Write CallContext IsCreate
                //   - Write CallContext CodeHash
                rw_counter: Delta(22.expr() + transfer_with_gas_fee.rw_delta()),
                call_id: To(call_id.expr()),
                is_root: To(true.expr()),
                is_create: To(tx_is_create.expr()),
                code_hash: To(cb.curr.state.code_hash.expr()),
                gas_left: To(gas_left.clone()),
                // There are a + 1 reversible writes:
                //  - a TransferWithGasFeeGadget
                //  - Callee Account Nonce
                reversible_write_counter: To(transfer_with_gas_fee.reversible_w_delta() + 1.expr()),
                log_id: To(0.expr()),
                ..StepStateTransition::new_context()
            });
        });

        // 2. Handle call to precompiled contracts.
        cb.condition(is_precompile.expr(), |cb| {
            cb.require_equal(
                "precompile should be zero code hash",
                // FIXME: see in opcodes.rs gen_begin_tx_ops
                no_callee_code.expr(),
                true.expr(),
            );
            // TODO: verify that precompile could fail in begin tx.
            // cb.require_equal(
            // "Tx to precompile should be persistent",
            // reversion_info.is_persistent(),
            // 1.expr(),
            // );

            cb.require_equal(
                "Go to EndDepositTx when Tx to precompile",
                cb.next
                    .execution_state_selector([ExecutionState::EndDepositTx]),
                1.expr(),
            );

            cb.require_step_state_transition(StepStateTransition {
                // 8 + TransferWithGasFeeGadget associated reads and writes:
                //   - Write CallContext TxId
                //   - Write CallContext RwCounterEndOfReversion
                //   - Write CallContext IsPersistent
                //   - Write CallContext IsSuccess
                //   - Write Account Balance (handle mint)
                //   - Write Account (Caller) Nonce
                //   - Write TxAccessListAccount (Caller)
                //   - Write TxAccessListAccount (Callee)
                //   - a TransferWithGasFeeGadget
                rw_counter: Delta(
                    8.expr()
                        + transfer_with_gas_fee.rw_delta()
                        // TRICKY:
                        // Process the reversion only for Precompile in begin TX. Since no
                        // associated opcodes could process reversion afterwards
                        // (corresponding to `handle_reversion` call in `gen_begin_tx_ops`).
                        // TODO:
                        // Move it to code of generating precompiled operations when implemented.
                        + not::expr(is_persistent.expr())
                            * transfer_with_gas_fee.reversible_w_delta(),
                ),
                call_id: To(call_id.expr()),
                ..StepStateTransition::any()
            });
        });

        // 3. Call to account with empty code.
        cb.condition(
            and::expr([
                not::expr(tx_is_create.expr()),
                no_callee_code.expr(),
                not::expr(is_precompile.expr()),
            ]),
            |cb| {
                cb.require_equal(
                    "Tx to account with empty code should be persistent",
                    reversion_info.is_persistent(),
                    1.expr(),
                );

                cb.require_equal(
                    "Go to EndDepositTx when Tx to account with empty code",
                    cb.next
                        .execution_state_selector([ExecutionState::EndDepositTx]),
                    1.expr(),
                );

                cb.require_step_state_transition(StepStateTransition {
                    // 9 + TransferWithGasFeeGadget associated reads and writes:
                    //   - Write CallContext TxId
                    //   - Write CallContext RwCounterEndOfReversion
                    //   - Write CallContext IsPersistent
                    //   - Write CallContext IsSuccess
                    //   - Write Account Balance (handle mint)
                    //   - Write Account Nonce
                    //   - Write TxAccessListAccount
                    //   - Write TxAccessListAccount
                    //   - Read Account CodeHash
                    //   - a TransferWithGasFeeGadget
                    rw_counter: Delta(9.expr() + transfer_with_gas_fee.rw_delta()),
                    call_id: To(call_id.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        // 4. Call to account with non-empty code.
        cb.condition(
            and::expr([not::expr(tx_is_create.expr()), not::expr(no_callee_code)]),
            |cb| {
                // Setup first call's context.
                for (field_tag, value) in [
                    (CallContextFieldTag::Depth, 1.expr()),
                    (CallContextFieldTag::CallerAddress, tx_caller_address.expr()),
                    (
                        CallContextFieldTag::CalleeAddress,
                        call_callee_address.expr(),
                    ),
                    (CallContextFieldTag::CallDataOffset, 0.expr()),
                    (
                        CallContextFieldTag::CallDataLength,
                        tx_call_data_length.expr(),
                    ),
                    (CallContextFieldTag::Value, tx_value.expr()),
                    (CallContextFieldTag::IsStatic, 0.expr()),
                    (CallContextFieldTag::LastCalleeId, 0.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
                    (CallContextFieldTag::IsRoot, 1.expr()),
                    (CallContextFieldTag::IsCreate, tx_is_create.expr()),
                    (CallContextFieldTag::CodeHash, phase2_code_hash.expr()),
                ] {
                    cb.call_context_lookup(true.expr(), Some(call_id.expr()), field_tag, value);
                }

                cb.require_step_state_transition(StepStateTransition {
                    // 22 + TransferWithGasFeeGadget associated reads and writes:
                    //   - Write CallContext TxId
                    //   - Write CallContext RwCounterEndOfReversion
                    //   - Write CallContext IsPersistent
                    //   - Write CallContext IsSuccess
                    //   - Write Account Balance (handle mint)
                    //   - Write Account Nonce
                    //   - Write TxAccessListAccount
                    //   - Write TxAccessListAccount
                    //   - Read Account CodeHash
                    //   - a TransferWithGasFeeGadget
                    //   - Write CallContext Depth
                    //   - Write CallContext CallerAddress
                    //   - Write CallContext CalleeAddress
                    //   - Write CallContext CallDataOffset
                    //   - Write CallContext CallDataLength
                    //   - Write CallContext Value
                    //   - Write CallContext IsStatic
                    //   - Write CallContext LastCalleeId
                    //   - Write CallContext LastCalleeReturnDataOffset
                    //   - Write CallContext LastCalleeReturnDataLength
                    //   - Write CallContext IsRoot
                    //   - Write CallContext IsCreate
                    //   - Write CallContext CodeHash
                    rw_counter: Delta(22.expr() + transfer_with_gas_fee.rw_delta()),
                    call_id: To(call_id.expr()),
                    is_root: To(true.expr()),
                    is_create: To(tx_is_create.expr()),
                    code_hash: To(phase2_code_hash.expr()),
                    gas_left: To(gas_left),
                    reversible_write_counter: To(transfer_with_gas_fee.reversible_w_delta()),
                    log_id: To(0.expr()),
                    ..StepStateTransition::new_context()
                });
            },
        );

        Self {
            tx_id,
            tx_type,
            tx_nonce,
            tx_gas,
            tx_gas_price,
            mint,
            mul_gas_fee_by_gas,
            tx_caller_address,
            tx_caller_address_is_zero,
            tx_callee_address,
            tx_callee_address_is_zero,
            call_callee_address,
            tx_is_create,
            tx_value,
            tx_mint,
            tx_call_data_length,
            tx_call_data_gas_cost,
            reversion_info,
            sufficient_gas_left,
            transfer_with_gas_fee,
            phase2_code_hash,
            intrinsic_gas_cost,
            is_empty_code_hash,
            is_precompile_lt,
            caller_nonce_hash_bytes,
            create,
            callee_not_exists,
            is_caller_callee_equal,
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
        let gas_fee = tx.gas_price * tx.gas;
        let zero = eth_types::Word::zero();

        let mut rws = StepRws::new(block, step);
        let mut add = 0;
        if tx.is_deposit() {
            add += 1;
        }
        rws.offset_add(7 + add);
        let mut callee_code_hash = zero;
        if !tx.is_create && !is_precompiled(&tx.callee_address.unwrap_or_default()) {
            callee_code_hash = rws.next().account_codehash_pair().1;
        }
        let callee_exists = is_precompiled(&tx.callee_address.unwrap_or_default())
            || (!tx.is_create && !callee_code_hash.is_zero());
        let caller_balance_sub_fee_pair = rws.next().account_balance_pair();
        let must_create = tx.is_create;
        if (!callee_exists && !tx.value.is_zero()) || must_create {
            callee_code_hash = rws.next().account_codehash_pair().1;
        }
        let mut caller_balance_sub_value_pair = (zero, zero);
        let mut callee_balance_pair = (zero, zero);
        if !tx.value.is_zero() {
            caller_balance_sub_value_pair = rws.next().account_balance_pair();
            callee_balance_pair = rws.next().account_balance_pair();
        };

        let (mint_balance, mint_balance_prev) =
            block.rws[step.rw_indices[BEGIN_TX_MINT_RWC_OFFSET]].account_value_pair();

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.tx_type
            .assign(region, offset, Value::known(F::from(tx.transaction_type)))?;
        self.tx_nonce
            .assign(region, offset, Value::known(F::from(tx.nonce)))?;
        self.tx_gas
            .assign(region, offset, Value::known(F::from(tx.gas)))?;
        self.tx_gas_price
            .assign(region, offset, Some(tx.gas_price.to_le_bytes()))?;
        self.tx_value
            .assign(region, offset, Some(tx.value.to_le_bytes()))?;
        self.mul_gas_fee_by_gas.assign(
            region,
            offset,
            tx.gas_price,
            tx.gas,
            tx.gas_price * tx.gas,
        )?;
        self.tx_mint
            .assign(region, offset, Some(tx.mint.to_le_bytes()))?;
        self.mint.assign(
            region,
            offset,
            mint_balance_prev,
            vec![tx.mint],
            mint_balance,
        )?;
        let caller_address = tx
            .caller_address
            .to_scalar()
            .expect("unexpected Address -> Scalar conversion failure");
        let callee_address = tx
            .callee_address
            .unwrap_or(Address::zero())
            .to_scalar()
            .expect("unexpected Address -> Scalar conversion failure");
        self.tx_caller_address
            .assign(region, offset, Value::known(caller_address))?;
        self.tx_caller_address_is_zero
            .assign(region, offset, caller_address)?;
        self.tx_callee_address
            .assign(region, offset, Value::known(callee_address))?;
        self.tx_callee_address_is_zero
            .assign(region, offset, callee_address)?;
        self.is_precompile_lt
            .assign(region, offset, callee_address, F::from(0xA))?;
        self.call_callee_address.assign(
            region,
            offset,
            Value::known(
                if tx.is_create {
                    get_contract_address(tx.caller_address, tx.nonce)
                } else {
                    tx.callee_address.unwrap_or(Address::zero())
                }
                .to_scalar()
                .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.is_caller_callee_equal.assign(
            region,
            offset,
            Value::known(F::from(caller_address == callee_address)),
        )?;
        self.tx_is_create
            .assign(region, offset, Value::known(F::from(tx.is_create as u64)))?;
        self.tx_call_data_length.assign(
            region,
            offset,
            Value::known(F::from(tx.call_data_length as u64)),
        )?;
        self.tx_call_data_gas_cost.assign(
            region,
            offset,
            Value::known(F::from(tx.call_data_gas_cost)),
        )?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.intrinsic_gas_cost
            .assign(region, offset, Value::known(F::from(step.gas_cost)))?;
        self.sufficient_gas_left
            .assign(region, offset, F::from(tx.gas - step.gas_cost))?;
        self.transfer_with_gas_fee.assign(
            region,
            offset,
            caller_balance_sub_fee_pair,
            caller_balance_sub_value_pair,
            callee_balance_pair,
            tx.value,
            gas_fee,
        )?;
        self.phase2_code_hash
            .assign(region, offset, region.word_rlc(callee_code_hash))?;
        let untrimmed_contract_addr = {
            let mut stream = RlpStream::new();
            stream.begin_list(2);
            stream.append(&tx.caller_address);
            stream.append(&eth_types::U256::from(tx.nonce));
            let rlp_encoding = stream.out().to_vec();
            keccak256(&rlp_encoding)
        };
        for (c, v) in self
            .caller_nonce_hash_bytes
            .iter()
            .rev()
            .zip(untrimmed_contract_addr.iter())
        {
            c.assign(region, offset, Value::known(F::from(*v as u64)))?;
        }
        self.is_empty_code_hash.assign_value(
            region,
            offset,
            region.word_rlc(callee_code_hash),
            region.empty_code_hash_rlc(),
        )?;
        self.callee_not_exists
            .assign_value(region, offset, region.word_rlc(callee_code_hash))?;

        let untrimmed_contract_addr = {
            let mut stream = ethers_core::utils::rlp::RlpStream::new();
            stream.begin_list(2);
            stream.append(&tx.caller_address);
            stream.append(&eth_types::U256::from(tx.nonce));
            let rlp_encoding = stream.out().to_vec();
            keccak256(&rlp_encoding)
        };
        for (c, v) in self
            .caller_nonce_hash_bytes
            .iter()
            .rev()
            .zip(untrimmed_contract_addr.iter())
        {
            c.assign(region, offset, Value::known(F::from(*v as u64)))?;
        }
        self.create.assign(
            region,
            offset,
            tx.caller_address,
            tx.nonce,
            Some(callee_code_hash),
            None,
        )?;
        Ok(())
    }
}

#[cfg(feature = "kroma")]
#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{self, bytecode, geth_types::DEPOSIT_TX_TYPE};
    use mock::{
        eth,
        test_ctx::{
            helpers::{account_0_code_account_1_no_code, system_deposit_tx},
            TestContext2_2,
        },
        tx_idx,
    };

    #[test]
    fn begin_tx_gadget_deposit() {
        // Get the execution steps from the external tracer

        let ctx = TestContext2_2::new(
            None,
            account_0_code_account_1_no_code(bytecode! { STOP }),
            |mut txs, accs| {
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .transaction_type(DEPOSIT_TX_TYPE);
                txs[tx_idx!(1)]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .transaction_type(DEPOSIT_TX_TYPE)
                    .mint(eth(1));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
