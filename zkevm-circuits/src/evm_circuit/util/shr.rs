

impl<F: Field> ShrWordsGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        a: util::Word<F>,
        shift: util::Word<F>,
    ) -> Self {


        // check combination of a_slice_lo_digits and a_slice_hi_digits == b_digits
        let mut shift_constraits = (0..4).map(|_| 0.expr()).collect::<Vec<Expression<F>>>();
        for transplacement in (0_usize)..(4_usize) {
            // generate the polynomial depends on the shift_div64
            let select_transplacement_polynomial =
                generate_lagrange_base_polynomial(shift_div64.expr(), transplacement, 0..4);
            for idx in 0..(4 - transplacement) {
                let tmpidx = idx + transplacement;
                // gupeng
                let merge_a = if idx + transplacement == (3_usize) {
                    a_slice_hi_digits[tmpidx].clone()
                } else {
                    a_slice_hi_digits[tmpidx].clone()
                        + a_slice_lo_digits[tmpidx + 1].clone() * shift_mod64_decpow.expr()
                };
                shift_constraits[idx] = shift_constraits[idx].clone()
                    + select_transplacement_polynomial.clone()
                        * select::expr(
                            shift_overflow.clone(),
                            b_digits[idx].clone(),
                            merge_a - b_digits[idx].clone(),
                        );
            }
            for idx in (4 - transplacement)..4 {
                shift_constraits[idx] = shift_constraits[idx].clone()
                    + select_transplacement_polynomial.clone() * b_digits[idx].clone();
            }
        }

        // for i in 0..4
        // a_slice_lo_digits[i] + a_slice_hi_digits * shift_mod64_pow
        // == a_digits[i]
        //
        // gupeng
        for idx in 0..4 {
            cb.require_equal(
                "a[idx] == a_slice_lo[idx] + a_slice_hi[idx] * shift_mod64_pow",
                a_slice_lo_digits[idx].clone()
                    + a_slice_hi_digits[idx].clone() * shift_mod64_pow.expr(),
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
                        + (select_transplacement_polynomial.clone() * a_slice_lo[nowidx].expr());
                }
                for idx in (8 - digit_transplacement)..8 {
                    let nowidx = (virtual_idx * 8 + idx) as usize;
                    equal_to_zero = equal_to_zero
                        + (select_transplacement_polynomial.clone() * a_slice_hi[nowidx].expr());
                }
            }
        }

        //check the specific 4 cells in 0..(1 << shift_mod8).
        //check another specific 4 cells in 0..(1 << (8 - shift_mod8)).
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
                    + select_transplacement_polynomial.clone() * a_slice_lo[nowidx].expr();
                let nowidx = (virtual_idx * 8 + 7 - digit_transplacement) as usize;
                slice_bits_polynomial[1] = slice_bits_polynomial[1].clone()
                    + select_transplacement_polynomial.clone() * a_slice_hi[nowidx].expr();
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

    }

    fn assign_witness(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        wa: &Word,
        wshift: &Word,
    ) -> Result<(), Error> {

        for virtual_idx in 0..4 {
            let mut tmp_a: u64 = 0;
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                tmp_a += (1u64 << (8 * idx)) * (a8s[now_idx] as u64);
            }
            // gupeng
            let mut slice_lo = if shift_mod64 == 0 {
                0
            } else {
                tmp_a % (1u64 << shift_mod64)
            };
            let mut slice_hi = if shift_mod64 == 0 {
                tmp_a
            } else {
                tmp_a / (1u64 << shift_mod64)
            };
        }

    }
}
