use crate::{
    evm_circuit::{
        table::{FixedTableTag, Lookup},
        util::math_gadget::{generate_lagrange_base_polynomial, IsZeroGadget},
        util::{self, constraint_builder::ConstraintBuilder, from_bytes, select, Cell},
    },
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::{
    circuit::Region,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub struct ShiftWordsGadget<F> {
    opcode: Expression<F>,
    a: util::Word<F>,
    shift: util::Word<F>,
    b: util::Word<F>,
    // slice_hi means the higher part of split digit
    // slice_lo means the lower part of split digit
    a_slice_hi: [Cell<F>; 32],
    a_slice_lo: [Cell<F>; 32],
    // shift_div64, shift_mod64_div8, shift_mod8
    // is used to seperate shift[0]
    shift_div64: Cell<F>,
    shift_mod64_div8: Cell<F>,
    shift_mod64_decpow: Cell<F>, // means 2^(8-shift_mod64)
    shift_mod64_pow: Cell<F>,    // means 2^shift_mod64
    shift_mod8: Cell<F>,
    // if combination of shift[1..32] == 0
    // shift_overflow will be equal to 0, otherwise 1.
    shift_overflow: Cell<F>,
    // is_zero will check combination of shift[1..32] == 0
    is_zero: IsZeroGadget<F>,
}

impl<F: Field> ShiftWordsGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        opcode: Expression<F>,
        a: util::Word<F>,
        shift: util::Word<F>,
    ) -> Self {
        let b = cb.query_word();
        let a_slice_hi = cb.query_bytes();
        let a_slice_lo = cb.query_bytes();
        let shift_div64 = cb.query_cell();
        let shift_mod64_div8 = cb.query_cell();
        let shift_mod64_decpow = cb.query_cell();
        let shift_mod64_pow = cb.query_cell();
        let shift_mod8 = cb.query_cell();
        let shift_overflow = cb.query_bool();

        // check (combination of shift[1..32] == 0) == 1 - shift_overflow
        let mut sum = 0.expr();
        (1..32).for_each(|idx| sum = sum.clone() + shift.cells[idx].expr());
        let is_zero = IsZeroGadget::construct(cb, sum);
        // if combination of shift[1..32] == 0
        // shift_overflow will be equal to 0, otherwise 1.
        cb.require_equal(
            "shift_overflow == shift > 256",
            shift_overflow.expr(),
            1.expr() - is_zero.expr(),
        );

        // rename variable:
        // shift_div64: a
        // shift_mod64_div8: b
        // shift_mod8: c
        // we split shift[0] to the equation:
        // shift[0] == a * 64 + b * 8 + c
        let shift_mod64 = 8.expr() * shift_mod64_div8.expr() + shift_mod8.expr();
        cb.require_equal(
            "shift[0] == shift_div64 * 64 + shift_mod64_div8 * 8 + shift_mod8",
            shift.cells[0].expr(),
            shift_div64.expr() * 64.expr() + shift_mod64.clone(),
        );

        // merge 8 8-bit cell for a 64-bit expression
        // for a, a_slice_hi, a_slice_lo, b
        let mut a_digits = vec![];
        let mut a_slice_hi_digits = vec![];
        let mut a_slice_lo_digits = vec![];
        let mut b_digits = vec![];
        for virtual_idx in 0..4 {
            let now_idx = (virtual_idx * 8) as usize;
            a_digits.push(from_bytes::expr(&a.cells[now_idx..now_idx + 8]));
            a_slice_lo_digits.push(from_bytes::expr(&a_slice_lo[now_idx..now_idx + 8]));
            a_slice_hi_digits.push(from_bytes::expr(&a_slice_hi[now_idx..now_idx + 8]));
            b_digits.push(from_bytes::expr(&b.cells[now_idx..now_idx + 8]));
        }

        // check combination of a_slice_lo_digits and a_slice_hi_digits == b_digits
        let mut shift_constraits = (0..4).map(|_| 0.expr()).collect::<Vec<Expression<F>>>();
        for transplacement in (0_usize)..(4_usize) {
            // generate the polynomial depends on the shift_div64
            let select_transplacement_polynomial =
                generate_lagrange_base_polynomial(shift_div64.expr(), transplacement, 0..4);
            for idx in 0..(4 - transplacement) {
                let tmpidx = idx + transplacement;
                // gupeng
                let merge_a = if idx == (0_usize) {
                    a_slice_lo_digits[idx].clone() * shift_mod64_pow.expr()
                } else {
                    a_slice_lo_digits[idx].clone() * shift_mod64_pow.expr()
                        + a_slice_hi_digits[idx - 1].clone()
                };
                shift_constraits[tmpidx] = shift_constraits[tmpidx].clone()
                    + select_transplacement_polynomial.clone()
                        * select::expr(
                            shift_overflow.expr(),
                            b_digits[tmpidx].clone(),
                            merge_a - b_digits[tmpidx].clone(),
                        );
            }
            for idx in 0..transplacement {
                shift_constraits[idx] = shift_constraits[idx].clone()
                    + select_transplacement_polynomial.clone() * b_digits[idx].clone();
            }
        }
        (0..4).for_each(|idx| {
            cb.require_zero(
                "merge a_slice_lo_digits and a_slice_hi_digits == b_digits",
                shift_constraits[idx].clone(),
            )
        });

        // for i in 0..4
        // a_slice_lo_digits[i] + a_slice_hi_digits * shift_mod64_decpow
        // == a_digits[i]
        //
        // gupeng
        for idx in 0..4 {
            cb.require_equal(
                "a[idx] == a_slice_lo[idx] + a_slice_hi[idx] * shift_mod64_decpow",
                a_slice_lo_digits[idx].clone()
                    + a_slice_hi_digits[idx].clone() * shift_mod64_decpow.expr(),
                a_digits[idx].clone(),
            );
        }

        // check serveral higher cells == 0 for slice_lo and slice_hi
        let mut equal_to_zero = 0.expr();
        for digit_transplacement in 0..8 {
            let select_transplacement_polynomial = generate_lagrange_base_polynomial(
                shift_mod64_div8.expr(),
                digit_transplacement,
                0..8,
            );
            for virtual_idx in 0..4 {
                // gupeng
                for idx in (digit_transplacement + 1)..8 {
                    let nowidx = (virtual_idx * 8 + idx) as usize;
                    equal_to_zero = equal_to_zero
                        + select_transplacement_polynomial.clone() * a_slice_hi[nowidx].expr();
                }
                for idx in (8 - digit_transplacement)..8 {
                    let nowidx = (virtual_idx * 8 + idx) as usize;
                    equal_to_zero = equal_to_zero
                        + select_transplacement_polynomial.clone() * a_slice_lo[nowidx].expr();
                }
            }
        }

        // check the specific 4 cells in 0..(1 << shift_mod8).
        // check another specific 4 cells in 0..(1 << (8 - shift_mod8)).
        for virtual_idx in 0..4 {
            // gupeng
            let mut slice_bits_polynomial = vec![0.expr(), 0.expr()];
            for digit_transplacement in 0..8 {
                let select_transplacement_polynomial = generate_lagrange_base_polynomial(
                    shift_mod64_div8.expr(),
                    digit_transplacement,
                    0..8,
                );
                let nowidx = (virtual_idx * 8 + digit_transplacement) as usize;
                slice_bits_polynomial[0] = slice_bits_polynomial[0].clone()
                    + select_transplacement_polynomial.clone() * a_slice_hi[nowidx].expr();
                let nowidx = (virtual_idx * 8 + 7 - digit_transplacement) as usize;
                slice_bits_polynomial[1] = slice_bits_polynomial[1].clone()
                    + select_transplacement_polynomial.clone() * a_slice_lo[nowidx].expr();
            }
            cb.add_lookup(
                "slice_bits range lookup",
                Lookup::Fixed {
                    tag: FixedTableTag::Bitslevel.expr(),
                    values: [
                        shift_mod8.expr(),
                        slice_bits_polynomial[0].clone(),
                        0.expr(),
                    ],
                },
            );
            cb.add_lookup(
                "slice_bits range lookup",
                Lookup::Fixed {
                    tag: FixedTableTag::Bitslevel.expr(),
                    values: [
                        8.expr() - shift_mod8.expr(),
                        slice_bits_polynomial[1].clone(),
                        0.expr(),
                    ],
                },
            );
        }

        // check:
        // 2^shift_mod64 == shift_mod64_pow
        // 2^(8-shift_mod64) == shift_mod64_decpow
        cb.add_lookup(
            "pow_of_two lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Pow64.expr(),
                values: [
                    shift_mod64,
                    shift_mod64_pow.expr(),
                    shift_mod64_decpow.expr(),
                ],
            },
        );

        cb.add_lookup(
            "shift_div64 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [2.expr(), shift_div64.expr(), 0.expr()],
            },
        );
        cb.add_lookup(
            "shift_mod64_div8 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [3.expr(), shift_mod64_div8.expr(), 0.expr()],
            },
        );
        cb.add_lookup(
            "shift_mod8 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [3.expr(), shift_mod8.expr(), 0.expr()],
            },
        );

        Self {
            opcode,
            a,
            shift,
            b,
            a_slice_hi,
            a_slice_lo,
            shift_div64,
            shift_mod64_div8,
            shift_mod64_decpow,
            shift_mod64_pow,
            shift_mod8,
            shift_overflow,
            is_zero,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        a: Word,
        shift: Word,
        b: Word,
    ) -> Result<(), Error> {
        self.assign_witness(region, offset, &a, &shift)?;
        self.a.assign(region, offset, Some(a.to_le_bytes()))?;
        self.shift
            .assign(region, offset, Some(shift.to_le_bytes()))?;
        self.b.assign(region, offset, Some(b.to_le_bytes()))?;
        Ok(())
    }

    pub(crate) fn b(&self) -> &util::Word<F> {
        &self.b
    }

    fn assign_witness(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        wa: &Word,
        wshift: &Word,
    ) -> Result<(), Error> {
        let a8s = wa.to_le_bytes();
        let shift = wshift.to_le_bytes()[0] as u128;
        let shift_div64 = shift / 64;
        let shift_mod64_div8 = shift % 64 / 8;
        let shift_mod64 = shift % 64;
        let shift_mod64_pow = 1_u128 << shift_mod64;
        let shift_mod64_decpow = (1_u128 << 64) / (shift_mod64_pow as u128);
        let shift_mod8 = shift % 8;
        let mut a_slice_hi = [0u8; 32];
        let mut a_slice_lo = [0u8; 32];

        for virtual_idx in 0..4 {
            let mut tmp_a: u64 = 0;
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                tmp_a += (1u64 << (8 * idx)) * (a8s[now_idx] as u64);
            }
            // gupeng
            let mut slice_lo = if shift_mod64 == 0 {
                tmp_a
            } else {
                tmp_a % (1u64 << (64 - shift_mod64))
            };
            let mut slice_hi = if shift_mod64 == 0 {
                0
            } else {
                tmp_a / (1u64 << (64 - shift_mod64))
            };
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                a_slice_lo[now_idx] = (slice_lo % (1 << 8)) as u8;
                a_slice_hi[now_idx] = (slice_hi % (1 << 8)) as u8;
                slice_lo >>= 8;
                slice_hi >>= 8;
            }
        }
        a_slice_hi.iter().zip(self.a_slice_hi.iter()).try_for_each(
            |(bt, assignee)| -> Result<(), Error> {
                assignee.assign(region, offset, Some(F::from(*bt as u64)))?;
                Ok(())
            },
        )?;
        a_slice_lo.iter().zip(self.a_slice_lo.iter()).try_for_each(
            |(bt, assignee)| -> Result<(), Error> {
                assignee.assign(region, offset, Some(F::from(*bt as u64)))?;
                Ok(())
            },
        )?;
        self.shift_div64
            .assign(region, offset, Some(F::from_u128(shift_div64)))?;
        self.shift_mod64_div8
            .assign(region, offset, Some(F::from_u128(shift_mod64_div8)))?;
        self.shift_mod64_decpow
            .assign(region, offset, Some(F::from_u128(shift_mod64_decpow)))?;
        self.shift_mod64_pow
            .assign(region, offset, Some(F::from_u128(shift_mod64_pow)))?;
        self.shift_mod8
            .assign(region, offset, Some(F::from_u128(shift_mod8)))?;

        let mut sum: u128 = 0;
        wshift.to_le_bytes().iter().for_each(|v| sum += *v as u128);
        sum -= shift as u128;
        let shift_overflow = sum != 0;
        self.is_zero.assign(region, offset, F::from_u128(sum))?;
        self.shift_overflow
            .assign(region, offset, Some(F::from_u128(shift_overflow as u128)))?;
        Ok(())
    }
}
