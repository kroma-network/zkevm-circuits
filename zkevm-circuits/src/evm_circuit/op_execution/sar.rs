use super::super::{
    BusMappingLookup, Case, Cell, Constraint, CoreStateInstance, ExecutionStep,
    FixedLookup, Lookup, Word,
};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error, plonk::Expression};
use std::{array, convert::TryInto};
use num::BigUint;

#[derive(Clone, Debug)]
struct SarSuccessAllocation<F> {
    selector: Cell<F>,
    a: Word<F>,
    b: Word<F>,
    shift: Word<F>,
    a_slice_front: [Cell<F>; 32],
    a_slice_back: [Cell<F>; 32],
    shift_div_by_64: Cell<F>,
    shift_mod_by_64_div_by_8: Cell<F>,
    shift_mod_by_64_decpow: Cell<F>,// means 2^(8-shift_mod_by_64) // means 2^(64-shift_mod_by_64)
    shift_mod_by_64_pow: Cell<F>,// means 2^shift_mod_by_64
    shift_mod_by_8: Cell<F>,
    sign_num: Cell<F>,
    high_pow: Cell<F>,
    m64: Cell<F>,
}

#[derive(Clone, Debug)]
pub struct SarGadget<F> {
    success: SarSuccessAllocation<F>,
    stack_underflow: Cell<F>,
    out_of_gas: (Cell<F>, Cell<F>),
}

impl<F: FieldExt> OpGadget<F> for SarGadget<F> {
    const RESPONSIBLE_OPCODES: &'static [OpcodeId] =
        &[OpcodeId::SAR];

    const CASE_CONFIGS: &'static [CaseConfig] = &[
        CaseConfig {
            case: Case::Success,
            num_word: 3,
            num_cell: 72, 
            will_halt: false,
        },
        CaseConfig {
            case: Case::StackUnderflow,
            num_word: 0,
            num_cell: 0,
            will_halt: true,
        },
        CaseConfig {
            case: Case::OutOfGas,
            num_word: 0,
            num_cell: 0,
            will_halt: true,
        },
    ];

    fn construct(case_allocations: Vec<CaseAllocation<F>>) -> Self {
        let [mut success, stack_underflow, out_of_gas]: [CaseAllocation<F>; 3] =
            case_allocations.try_into().unwrap();
        Self {
            success: SarSuccessAllocation {
                selector: success.selector,
                a: success.words.pop().unwrap(),
                b: success.words.pop().unwrap(),
                shift: success.words.pop().unwrap(),
                a_slice_front: success
                    .cells
                    .drain(0..32)
                    .collect::<Vec<Cell<F>>>()
                    .try_into()
                    .unwrap(),
                a_slice_back: success
                    .cells
                    .drain(0..32)
                    .collect::<Vec<Cell<F>>>()
                    .try_into()
                    .unwrap(),
                shift_div_by_64: success.cells.pop().unwrap(),
                shift_mod_by_64_div_by_8: success.cells.pop().unwrap(),
                shift_mod_by_64_decpow: success.cells.pop().unwrap(),
                shift_mod_by_64_pow: success.cells.pop().unwrap(),
                shift_mod_by_8: success.cells.pop().unwrap(),
                sign_num: success.cells.pop().unwrap(),
                high_pow: success.cells.pop().unwrap(),
                m64: success.cells.pop().unwrap(),
            },
            stack_underflow: stack_underflow.selector,
            out_of_gas: (
                out_of_gas.selector,
                out_of_gas.resumption.unwrap().gas_available,
            ),
        }
    }

    fn constraints(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
    ) -> Vec<Constraint<F>> {
        let OpExecutionState { opcode, .. } = &state_curr;

        let common_polys = vec![
            (opcode.expr() - OpcodeId::SAR.expr()),
        ];

        let success = {
            let state_transition_constraints = vec![
                state_next.global_counter.expr()
                    - (state_curr.global_counter.expr() + 3.expr()),
                state_next.stack_pointer.expr()
                    - (state_curr.stack_pointer.expr() + 1.expr()),
                state_next.program_counter.expr()
                    - (state_curr.program_counter.expr() + 1.expr()),
                state_next.gas_counter.expr()
                    - (state_curr.gas_counter.expr() + GasCost::FASTEST.expr()),
            ];

            let SarSuccessAllocation {
                selector,
                a,
                b,
                shift,
                a_slice_front,
                a_slice_back,
                shift_div_by_64,
                shift_mod_by_64_div_by_8,
                shift_mod_by_64_decpow,
                shift_mod_by_64_pow,
                shift_mod_by_8,
                sign_num,
                high_pow,
                m64,
            } = &self.success;

            let shift_mod_by_64 = shift_mod_by_64_div_by_8.expr() * 8.expr() + shift_mod_by_8.expr();  
            //merge 8 8-bit cell for a 64-bit expression for a, a_slice_front, a_slice_back, b
            let mut a_digits = vec![];
            let mut a_slice_front_digits = vec![];
            let mut a_slice_back_digits = vec![];
            let mut b_digits = vec![];

            for virtual_idx in 0..4 {
                let mut tmp_a = 0.expr();
                let mut tmp_a_slice_front = 0.expr();
                let mut tmp_a_slice_back = 0.expr();
                let mut tmp_b = 0.expr();                                           
                let mut radix = Expression::Constant(F::from_u64(1u64));
                for idx in 0..8 {
                    let now_idx = (virtual_idx * 8 + idx) as usize;
                    tmp_a = tmp_a + radix.clone() * a.cells[now_idx].expr();
                    tmp_a_slice_back = tmp_a_slice_back + radix.clone() * a_slice_back[now_idx].expr();
                    tmp_a_slice_front = tmp_a_slice_front + radix.clone() * a_slice_front[now_idx].expr();
                    tmp_b = tmp_b + radix.clone() * b.cells[now_idx].expr();
                    radix = radix * (1 << 8).expr();
                }
                //存储每一组的数和
                a_digits.push(tmp_a);
                a_slice_back_digits.push(tmp_a_slice_back);
                a_slice_front_digits.push(tmp_a_slice_front);
                b_digits.push(tmp_b);
            }            
            
            //we split shift to the equation: shift = shift_div_by_64 * 64 + shift_mod_by_64_div_by_8 * 8 + shift_mod_by_8
            let mut sar_constraints = vec![];
            for idx in 0..4 {
                sar_constraints.push(0.expr());
            }
            for transplacement in (0 as usize)..(4 as usize) {
                //generate the polynomial depends on the shift_div_by_64
                let select_transplacement_polynomial = generate_polynomial(shift_div_by_64.clone(), transplacement as u64, 4u64);
                for idx in 0..(4 - transplacement) {    
                    let tmpidx = idx + transplacement;
                    let merge_a = if idx + transplacement == (3 as usize){
                        a_slice_front_digits[tmpidx].clone() + sign_num.expr() * high_pow.expr()
                    } else {            
                        a_slice_front_digits[tmpidx].clone() + a_slice_back_digits[tmpidx + 1].clone() * shift_mod_by_64_decpow.expr()
                    };
                    sar_constraints[idx] = sar_constraints[idx].clone() + 
                        select_transplacement_polynomial.clone() * (merge_a - b_digits[idx].clone());
                }
                for idx in (4 - transplacement)..4 {
                    sar_constraints[idx] = sar_constraints[idx].clone() + select_transplacement_polynomial.clone() * (b_digits[idx].clone()
                        - sign_num.expr() * m64.expr());
                }
            }

            let shift_split_constraints = vec![
                shift.expr() - shift_div_by_64.expr() * 64.expr() - shift_mod_by_64.clone()
            ];

            let mut merge_constraints = vec![];
            for idx in 0..4 {
                merge_constraints.push(a_slice_back_digits[idx].clone() + a_slice_front_digits[idx].clone() * shift_mod_by_64_pow.expr() - a_digits[idx].clone());
            }

            let slice_equal_to_zero_constraints = {
                let mut slice_equal_to_zero = 0.expr();
                for digit_transplacement in 0..8 {
                    let select_transplacement_polynomial = generate_polynomial(shift_mod_by_64_div_by_8.clone(), digit_transplacement as u64, 8u64);
                    for virtual_idx in 0..4 {
                        for idx in (digit_transplacement + 1) .. 8 {
                            let nowidx = (virtual_idx * 8 + idx) as usize;
                            slice_equal_to_zero = 
                                slice_equal_to_zero + (select_transplacement_polynomial.clone() * a_slice_back[nowidx].expr());
                        }
                        for idx in (8 - digit_transplacement) .. 8 {
                            let nowidx = (virtual_idx * 8 + idx) as usize;
                            slice_equal_to_zero = 
                                slice_equal_to_zero + (select_transplacement_polynomial.clone() * a_slice_front[nowidx].expr());
                        }
                    }
                }
                vec![slice_equal_to_zero]
            };

            //i = 1..32
            //check shift[i] = 0
            let shift_range_constraints = {
                let mut sumc = 0.expr();
                for idx in 1..32 {
                    sumc = sumc + shift.cells[idx].expr();
                }
                vec![sumc]
            };
            
            let sign_constraints = vec![sign_num.expr() * (1.expr() - sign_num.expr())];
            //check the specific 4 cells for shift_mod_by_8 bits and 4 cells for (8 - shift_mod_by_8) bits.
            let mut slice_bits_lookups = vec![];
            for virtual_idx in 0..4 {
                let mut slice_bits_polynomial = vec![0.expr(), 0.expr()];
                for digit_transplacement in 0..8 {
                    let select_transplacement_polynomial = generate_polynomial(shift_mod_by_64_div_by_8.clone(), digit_transplacement as u64, 8u64);
                    let nowidx = (virtual_idx * 8 + digit_transplacement) as usize;
                    slice_bits_polynomial[0] = slice_bits_polynomial[0].clone() + select_transplacement_polynomial.clone() * a_slice_back[nowidx].expr();
                    let nowidx = (virtual_idx * 8 + 7 - digit_transplacement) as usize;
                    slice_bits_polynomial[1] = slice_bits_polynomial[1].clone() + select_transplacement_polynomial.clone() * a_slice_front[nowidx].expr();
                }
                slice_bits_lookups.push(
                    Lookup::FixedLookup(
                        FixedLookup::Bitslevel,
                        [shift_mod_by_8.expr(), slice_bits_polynomial[0].clone(), 0.expr()]
                    )
                );
                slice_bits_lookups.push(
                    Lookup::FixedLookup(
                        FixedLookup::Bitslevel,
                        [(8.expr() - shift_mod_by_8.expr()), slice_bits_polynomial[1].clone(), 0.expr()]
                    )
                );
            }

            //check 2^shift_mod_by_64 == shift_mod_by_64_pow && 2^(8-shift_mod_by_64) == shift_mod_by_64_pow
            let pow_lookups = vec![
                Lookup::FixedLookup(
                    FixedLookup::Pow64,
                    [shift_mod_by_64.clone(), shift_mod_by_64_pow.expr(), shift_mod_by_64_decpow.expr()],
                )
            ];

            let given_value_lookups = vec![
                Lookup::FixedLookup(
                    FixedLookup::Bitslevel,
                    [2.expr(), shift_div_by_64.expr(), 0.expr()],//shift_mod_by_64<2^2
                ),
                Lookup::FixedLookup(
                    FixedLookup::Bitslevel,
                    [3.expr(), shift_mod_by_64_div_by_8.expr(), 0.expr()],//shift_mod_by_64_div_by_8<2^3
                ),
                Lookup::FixedLookup(
                    FixedLookup::Bitslevel,
                    [3.expr(), shift_mod_by_8.expr(), 0.expr()],//shift_mod_by_8<2^3
                ),
            ];

            #[allow(clippy::suspicious_operation_groupings)]
            let bus_mapping_lookups = vec![//busmapping check
                Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: 0,
                    value: shift.expr(),
                    is_write: false,
                }),
                Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: 1,
                    value: a.expr(),
                    is_write: false,
                }),
                Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: 1,
                    value: b.expr(),
                    is_write: true,
                }),
            ];

            //check all cells for slice_back and slice_front are in [0,255]
            let slice_front_range_lookups = a_slice_front
                .iter()
                .map(|cell| {
                    Lookup::FixedLookup(
                        FixedLookup::Range256,
                        [cell.expr(), 0.expr(), 0.expr()],
                    )
                })
                .collect();

            let slice_back_range_lookups = a_slice_back
                .iter()
                .map(|cell| {
                    Lookup::FixedLookup(
                        FixedLookup::Range256,
                        [cell.expr(), 0.expr(), 0.expr()],
                    )
                })
                .collect();

            Constraint {
                name: "ShrGadget success",
                selector: selector.expr(),
                polys: [
                    state_transition_constraints,
                    shift_split_constraints,
                    shift_range_constraints,
                    sar_constraints.try_into().unwrap(),
                    merge_constraints,
                    slice_equal_to_zero_constraints,
                    sign_constraints,
                ]
                .concat(),
                lookups: [
                    slice_bits_lookups,
                    pow_lookups,
                    given_value_lookups,
                    bus_mapping_lookups,
                    slice_front_range_lookups,
                    slice_back_range_lookups,
                ].concat(),
            }
        };

        let stack_underflow = {
            let stack_pointer = state_curr.stack_pointer.expr();
            Constraint {
                name: "SarGadget stack underflow",
                selector: self.stack_underflow.expr(),
                polys: vec![
                    (stack_pointer.clone() - 1024.expr())
                        * (stack_pointer - 1023.expr()),
                ],
                lookups: vec![],
            }
        };

        let out_of_gas = {
            let (selector, gas_available) = &self.out_of_gas;
            let gas_overdemand = state_curr.gas_counter.expr()
                + GasCost::FASTEST.expr()
                - gas_available.expr();
            Constraint {
                name: "SarGadget out of gas",
                selector: selector.expr(),
                polys: vec![
                    (gas_overdemand.clone() - 1.expr())
                        * (gas_overdemand.clone() - 2.expr())
                        * (gas_overdemand - 3.expr()),
                ],
                lookups: vec![],
            }
        };

        array::IntoIter::new([success, stack_underflow, out_of_gas])
            .map(move |mut constraint| {
                constraint.polys =
                    [common_polys.clone(), constraint.polys].concat();
                constraint
            })
            .collect()
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        core_state: &mut CoreStateInstance,
        execution_step: &ExecutionStep,
    ) -> Result<(), Error> {
        match execution_step.case {
            Case::Success => {
                self.assign_success(region, offset, core_state, execution_step)
            }
            Case::StackUnderflow => {
                unimplemented!()
            }
            Case::OutOfGas => {
                unimplemented!()
            }
            _ => unreachable!(),
        }
    }
}

fn generate_polynomial<F:FieldExt>(now_cell: Cell<F>, now_num: u64, lim: u64) -> Expression<F> {
    //println!("generate_polynomial!");
    let mut now_expression = Expression::Constant(F::from_u64(1u64));
    let mut now_invert_expression = now_expression.clone();
    for not_equal_num in 0..lim {
        if not_equal_num != now_num {
            now_expression = now_expression * (now_cell.expr() - not_equal_num.expr());
            let invert = if now_num < not_equal_num {
                -F::from_u64(not_equal_num.clone() as u64 - now_num).invert().unwrap_or(F::zero())
            } else {
                F::from_u64(now_num - not_equal_num.clone() as u64).invert().unwrap_or(F::zero())
            };
            now_invert_expression = now_invert_expression * invert;
        }
    }
    now_expression * now_invert_expression
}

fn generate_high<F:FieldExt>(shift_mod_by_64_div_by_8: Cell<F>, shift_mod_by_8: Cell<F>) -> Expression<F>{
    //TODO: 怎么生成它的多项式?
    let mut res = Expression::Constant(F::from_u64(0u64));
    let count = shift_mod_by_64_div_by_8.expr() * 8.expr() + shift_mod_by_8.expr();
    for idx in 0..64{
        res = 1.expr() - (count.clone()-idx.expr());
    }
    
    res
}

impl<F: FieldExt> SarGadget<F>{
    fn assign_success(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        core_state: &mut CoreStateInstance,
        execution_step: &ExecutionStep,
    ) -> Result<(), Error>{
        core_state.global_counter += 3;
        core_state.program_counter += 1;
        core_state.stack_pointer += 1;
        core_state.gas_counter += 3;

        self.success.a.assign(
            region,
            offset,
            Some(execution_step.values[0].to_word()),
        )?;
        self.success.b.assign(
            region,
            offset,
            Some(execution_step.values[1].to_word()),
        )?;
        self.success.shift.assign(
            region,
            offset,
            Some(execution_step.values[2].to_word()),
        )?;
        self.success.shift.assign(
            region,
            offset,
            Some(execution_step.values[2].to_word()),
        )?;
        self.success
            .a_slice_front
            .iter()
            .zip(execution_step.values[3].to_word().iter())
            .map(|(alloc, value)| {
                alloc.assign(region, offset, Some(F::from_u64(*value as u64)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.success
            .a_slice_back
            .iter()
            .zip(execution_step.values[4].to_word().iter())
            .map(|(alloc, value)| {
                alloc.assign(region, offset, Some(F::from_u64(*value as u64)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.success.shift_div_by_64.assign(
            region,
            offset,
            Some(F::from_u64(
                execution_step.values[5].to_bytes_le()[0] as u64
            ))
        )?;
        self.success.shift_mod_by_64_div_by_8.assign(
            region,
            offset,
            Some(F::from_u64(
                execution_step.values[6].to_bytes_le()[0] as u64
            ))
        )?;
        let shift_mod_by_64_decpow_digits = execution_step.values[7].to_u64_digits();
        let shift_mod_by_64_decpow = {
            if shift_mod_by_64_decpow_digits.is_empty() {
                F::zero()
            } else {
                let sum = F::from_u64(1u64 << 63) * F::from_u64(2u64);
                if shift_mod_by_64_decpow_digits.len() == (2 as usize) {
                    sum
                } else {
                    F::from_u64(shift_mod_by_64_decpow_digits[0])
                }
            }
        };
        self.success.shift_mod_by_64_decpow.assign(
            region,
            offset,
            Some(shift_mod_by_64_decpow)
        )?;

        let shift_mod_by_64_pow_digits = execution_step.values[8].to_u64_digits();
        let shift_mod_by_64_pow = F::from_u64(if shift_mod_by_64_pow_digits.is_empty() {
            0u64
        } else {
            shift_mod_by_64_pow_digits[0]
        });
        self.success.shift_mod_by_64_pow.assign(
            region,
            offset,
            Some(shift_mod_by_64_pow)
        )?;
        self.success.shift_mod_by_8.assign(
            region,
            offset,
            Some(F::from_u64(
                execution_step.values[9].to_bytes_le()[0] as u64
            ))
        )?;
        self.success.sign_num.assign(
            region,
            offset,
            Some(F::from_u64(
                execution_step.values[10].to_bytes_le()[0] as u64
            ))
        )?;

        let high_pow_digits = execution_step.values[11].to_u64_digits();
        let high_pow = F::from_u64(if high_pow_digits.is_empty() {
            0u64
        } else {
            high_pow_digits[0]
        });
        self.success.high_pow.assign(
            region,
            offset,
            Some(high_pow)
        )?;

        let m64_digits = execution_step.values[12].to_u64_digits();
        let m64 = F::from_u64(if m64_digits.is_empty() {
            0u64
        } else {
            m64_digits[0]
        });
        self.success.m64.assign(
            region,
            offset,
            Some(m64)
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::super::{
        test::TestCircuit, Case, ExecutionStep, Operation,
    };
    use crate::util::ToWord;
    use bus_mapping::{evm::OpcodeId, operation::Target};
    use halo2::{arithmetic::FieldExt, dev::MockProver};
    use num::BigUint;
    use rand::Rng;
    use pasta_curves::pallas::Base;

    macro_rules! try_test_circuit {
        ($execution_step:expr, $operations:expr, $result:expr) => {{
            let circuit =
                TestCircuit::<Base>::new($execution_step, $operations);
            let prover = MockProver::<Base>::run(10, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }

    fn generate_high(shift_mod_by_64_div_by_8: &u64, shift_mod_by_8: &u64) -> u128 {
        let count = 8 * shift_mod_by_64_div_by_8 + shift_mod_by_8;
        let res = (1 << 64u64) - (1 << (64-count));
        res
    }
    fn result_generate(a: &BigUint, shift: &u64) -> (
        BigUint, BigUint, BigUint, BigUint, BigUint, BigUint,BigUint, BigUint, BigUint, BigUint,BigUint,u64, u64
    ) {
        let a8s = a.to_word();
        let sign_num = if a8s[31] >= 128 {
            1 as u8
        } else {
            0 as u8
        };
        println!("sign_num: {}", sign_num);
        let mut b8s = (a >> shift).to_word();
        let shift_div_by_64 = shift / 64;
        let shift_mod_by_64_div_by_8 = shift % 64 / 8;
        let shift_mod_by_64 = shift % 64;
        let shift_mod_by_64_pow = 1u64 << shift_mod_by_64;
        let shift_mod_by_64_decpow = (1u128 << 64) / (shift_mod_by_64_pow as u128); 
        let shift_mod_by_8 = shift % 8;
        println!("b: {}", a >> shift);
        //println!("b8: {:?}",b8s);
        println!("shift_div_by_64: {}", shift_div_by_64);
        println!("shift_mod_by_64_pow: {}",shift_mod_by_64_pow);
        println!("shift_mod_by_64_decpow: {}",shift_mod_by_64_decpow);
        println!("shift: {}", shift);
        println!("shift_mod_by_64 : {}", shift_mod_by_64);
        println!("shift_mod_by_64_div_by_8 : {}", shift_mod_by_64_div_by_8);
        println!("shift_mod_by_8 : {}", shift_mod_by_8);
        
        //let mut b1 = b8s;
        let high_cell = (shift_div_by_64 * 8 + shift_mod_by_64_div_by_8) as usize;
        if sign_num == 1{ 
            let mut idx = 0;
            while idx != (high_cell) {
                b8s[(31-idx) as usize] = 255u8;
                idx = idx + 1;
            }
            let m8 = if shift_mod_by_8 == 0 {
                0
            } else {
                255 - (1 << (8-shift_mod_by_8) as u16) + 1
            };
            b8s[31-high_cell] = b8s[31-high_cell] + m8;
        }
        println!("b8s: {:?}", b8s);

        let mut a_slice_front = [0u8; 32];
        let mut a_slice_back = [0u8; 32];
        let mut suma :u64 = 0;
        let mut sumb :u64 = 0;

        for virtual_idx in 0..4 {
            let mut tmp_a :u64 = 0;
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                tmp_a = tmp_a + (1u64 << (8 * idx)) * (a8s[now_idx] as u64);
                suma = suma + a8s[now_idx] as u64;
                sumb = sumb + b8s[now_idx] as u64;
            }
            let mut slice_back = 
                if shift_mod_by_64 == 0 { 
                    tmp_a 
                } else { 
                    tmp_a % (1u64 << shift_mod_by_64)
                };
            let mut slice_front = 
                if shift_mod_by_64 == 0 {
                    0   
                } else {
                    tmp_a / (1u64 << shift_mod_by_64)
                };
            assert_eq!(slice_front * (1u64 << shift_mod_by_64) + slice_back, tmp_a);
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                a_slice_back[now_idx] = (slice_back % (1 << 8)) as u8;
                a_slice_front[now_idx] = (slice_front % (1 << 8)) as u8;
                slice_back = slice_back >> 8;
                slice_front = slice_front >> 8;
            }
        }

        for idx in 0..32 {
            print!("{} ",a_slice_back[idx]);
        }println!("");
        for idx in 0..32 {
            print!("{} ",a_slice_front[idx]);
        }println!("");
       
        let high_pow = generate_high(&shift_mod_by_64_div_by_8, &shift_mod_by_8);
        let mut m64 = [0u8; 8];
        for idx in 0..8 {
            m64[idx as usize] = 255u8;
        }
        let m64 = BigUint::from_bytes_le(&m64);
        println!("m64: {}", m64);
       
        (
            BigUint::from_bytes_le(&b8s),
            BigUint::from_bytes_le(&a_slice_front),
            BigUint::from_bytes_le(&a_slice_back),
            BigUint::from(shift_div_by_64),
            BigUint::from(shift_mod_by_64_div_by_8),
            BigUint::from(shift_mod_by_64_decpow),
            BigUint::from(shift_mod_by_64_pow),
            BigUint::from(shift_mod_by_8),
            BigUint::from(sign_num),
            BigUint::from(high_pow),
            m64,
            suma,
            sumb,
        )
    }

    #[test]
    fn sar_gadget() {
        let rng = rand::thread_rng();
        let mut vec_a = vec![];
        for idx in 0..32 {
            vec_a.push(rng.clone().gen_range(0, 255));
        }

        for idx in 0..32 {
            print!("{} ",vec_a[idx]);
        }
        println!("");

        let a = BigUint::from_bytes_le(&vec_a);
        let a_bits = a.bits();
        println!("a: {}", a);
        println!("a_bits: {}", a_bits);
        let shift = rng.clone().gen_range(0, a_bits) as u64;
        let bits_num = if a_bits % 8 == 0 {
            a_bits / 8
        } else {
            a_bits / 8 + 1
        };
        let mut push_bigint = [0u8; 32];
        for idx in 0..bits_num {
            push_bigint[idx as usize] = 1u8;
        }

        println!("push_bigint: {:?}", push_bigint);
        let push_bigint = BigUint::from_bytes_le(&push_bigint);
        println!("push_bigint: {}", push_bigint);
        let (
            b,
            a_slice_front,
            a_slice_back,
            shift_div_by_64,    
            shift_mod_by_64_div_by_8,
            //shift_mod_by_64,
            shift_mod_by_64_decpow,
            shift_mod_by_64_pow,
            shift_mod_by_8,
            sign_num,
            high_pow,
            m64,
            suma,
            sumb,
        ) = result_generate(&a, &shift);

        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH1,
                    case: Case::Success,
                    values: vec![BigUint::from(shift), BigUint::from(0x01_u64)],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH32,//it has really low probability to have less than 248bits input so just use PUSH32 here.
                    case: Case::Success,
                    values: vec![a.clone(), push_bigint],
                },
                ExecutionStep {
                    opcode: OpcodeId::SAR,
                    case: Case::Success,
                    values: vec![
                        a.clone(),
                        b.clone(),
                        BigUint::from(shift),
                        a_slice_front.clone(),
                        a_slice_back.clone(),
                        shift_div_by_64.clone(),
                        shift_mod_by_64_div_by_8.clone(),
                        shift_mod_by_64_decpow.clone(),
                        shift_mod_by_64_pow.clone(),
                        shift_mod_by_8.clone(),
                        sign_num.clone(),
                        high_pow.clone(),
                        m64.clone(),
                    ],
                }
            ],
            vec![
                Operation {
                    gc: 1,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(shift),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 2,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        Base::from_u64(suma),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 3,
                    target: Target::Stack,
                    is_write: false,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        Base::from_u64(shift),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 4,
                    target: Target::Stack,
                    is_write: false,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(suma),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 5,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(sumb),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }
}