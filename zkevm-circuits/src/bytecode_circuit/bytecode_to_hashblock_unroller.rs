use crate::{
    evm_circuit::util::{
        and, constraint_builder::BaseConstraintBuilder, not, or, select, RandomLinearCombination,
    },
    table::{BytecodeFieldTag, BytecodeTable, DynamicTableColumns, KeccakTable, PoseidonHashTable},
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, Word};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
    poly::Rotation,
};
use keccak256::plain::Keccak;
use std::vec;

use super::param::PUSH_TABLE_WIDTH;
/// Public data for the bytecode
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BytecodeRow<F: Field> {
    code_hash: F,
    tag: F,
    index: F,
    is_code: F,
    value: F,
}

/// Unrolled bytecode
#[derive(Clone, Debug, PartialEq)]
pub struct UnrolledBytecode<F: Field> {
    pub(crate) bytes: Vec<u8>,
    rows: Vec<BytecodeRow<F>>,
}

#[derive(Clone, Debug)]
pub(crate) struct FieldTable<const BYTES_IN_FIELD: usize> {
    control_length: Column<Advice>,
    bytes_in_field_index: Column<Advice>,
    bytes_in_field_inv: Column<Advice>,
    is_field_border: Column<Advice>,
    final_padding_shift: Column<Advice>,
    field_index: Column<Advice>,
    field_index_inv: Column<Advice>,
}

impl<const BYTES_IN_FIELD: usize> FieldTable<BYTES_IN_FIELD> {

    /// Construct a new table
    pub(crate) fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            control_length: meta.advice_column(),
            bytes_in_field_index: meta.advice_column(),
            bytes_in_field_inv: meta.advice_column(),
            is_field_border: meta.advice_column(),
            final_padding_shift: meta.advice_column(),
            field_index: meta.advice_column(),
            field_index_inv: meta.advice_column(),
        }
    }

    /// Assign a blank row (at padding or start line of each bytecodes)
    pub(crate) fn assign_blank_row<F: Field, const WIDTH: usize>(
        &self, 
        region: &mut Region<F>, 
        offset: usize, 
    ) -> Result<(), Error> {
        for (name, column) in [
            ("control length blank", self.control_length),
            ("bytes in field blank", self.bytes_in_field_index),
            ("bytes in field inv blank", self.bytes_in_field_inv),
            ("field border blank", self.is_field_border),
            ("padding shift blank", self.final_padding_shift),
            ("field index blank", self.field_index),
            ("field index inv blank", self.field_index_inv),
        ] {
            region.assign_advice(
                || format!("assign {} {}", name, offset),
                column,
                offset,
                || Value::known(F::zero()),
            )?;
        }

        Ok(())
    }

    /// Assign a row, all of the value is determinded by current bytes progress and the hash width
    pub(crate) fn assign_row<F: Field, const WIDTH: usize>(
        &self, 
        region: &mut Region<F>, 
        offset: usize, 
        bytes_prog: (usize, usize)
    ) -> Result<(), Error> {

        let (bytes_fw, bytes_left) = bytes_prog;

        region.assign_advice(
            || format!("control length {}", offset),
            self.control_length,
            offset,
            || Value::known(F::from(bytes_left as u64)),
        )?;

        let bif_index = bytes_fw % BYTES_IN_FIELD;

        region.assign_advice(
            || format!("bytes in field {}", offset),
            self.bytes_in_field_inv,
            offset,
            || Value::known(F::from((if bif_index == 0 {BYTES_IN_FIELD} else {bif_index}-1) as u64)),
        )?;

        region.assign_advice(
            || format!("field border {}", offset),
            self.is_field_border,
            offset,
            || Value::known(if bif_index == 0 {F::one()} else {F::zero()}),
        )?;

        region.assign_advice(
            || format!("final padding shift {}", offset),
            self.final_padding_shift,
            offset,
            || Value::known(if bif_index == 0 {F::zero()} else {F::from(u64::pow(256, (BYTES_IN_FIELD - bif_index) as u32))}),
        )?;

        region.assign_advice(
            || format!("bytes in field inv {}", offset),
            self.bytes_in_field_index,
            offset,
            || Value::known(if bif_index == 0 {F::zero()} else {F::from((BYTES_IN_FIELD - bif_index) as u64).invert().unwrap()}),
        )?;

        let fl_index = (bytes_fw / BYTES_IN_FIELD) % WIDTH;

        region.assign_advice(
            || format!("field index {}", offset),
            self.field_index,
            offset,
            || Value::known(F::from((if fl_index == 0 {WIDTH} else { fl_index }-1) as u64)),
        )?;

        region.assign_advice(
            || format!("field index inv {}", offset),
            self.field_index_inv,
            offset,
            || Value::known(if fl_index == 0 {F::zero()} else {F::from((WIDTH - fl_index) as u64).invert().unwrap()}),
        )?;

        Ok(())
    }

    /// build expression for selector of indexs on each field, for small WIDTH (current 2)
    /// we can just use lagrange polynomial
    pub(crate) fn field_selector<F: Field, const WIDTH: usize>(
        &self,
        meta: &mut VirtualCells<F>,
        ind: usize,
    ) -> Expression<F> {
        let mut denominators: Vec<F> = (0..(WIDTH + 1))
            .map(|v| F::from(ind as u64) - F::from(v as u64))
            .collect();
        denominators.swap_remove(ind);
        let denominator = denominators.into_iter().fold(F::one(), |acc, v| v * acc);
        assert_ne!(denominator, F::zero());
    
        let mut factors: Vec<Expression<F>> = (0..(WIDTH + 1))
            .map(|v| meta.query_advice(self.field_index, Rotation::cur()) - v.expr())
            .collect();
        factors.swap_remove(ind);
        factors.into_iter().fold(
            Expression::Constant(denominator.invert().unwrap()),
            |acc, f| acc * f,
        )
    }

}

/// specify byte in field for encoding bytecode
pub const HASHBLOCK_BYTES_IN_FIELD : usize = 16;

#[derive(Clone, Debug)]
/// Bytecode circuit configuration
pub struct Config<F> {
    minimum_rows: usize,
    q_enable: Column<Fixed>,
    q_first: Column<Fixed>,
    q_last: Selector,
    bytecode_table: BytecodeTable,
    field_table: FieldTable<HASHBLOCK_BYTES_IN_FIELD>,
    push_rindex: Column<Advice>,
    hash_input_lc: Column<Advice>,
    code_length: Column<Advice>,
    byte_push_size: Column<Advice>,    
    is_final: Column<Advice>,
    padding: Column<Advice>,
    push_rindex_inv: Column<Advice>,
    push_rindex_is_zero: IsZeroConfig<F>,
    length_inv: Column<Advice>,
    length_is_zero: IsZeroConfig<F>,
    push_table: [Column<Fixed>; PUSH_TABLE_WIDTH],
    pub(crate) hash_table: PoseidonHashTable,
}

impl<F: Field> Config<F> {

    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        _randomness: Expression<F>, // randonmess is not needed in hashblock unroller, just kept for calling compatible
        bytecode_table: BytecodeTable,
        hash_table: PoseidonHashTable,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_last = meta.selector();
        let value = bytecode_table.value;
        let push_rindex = meta.advice_column();
        let hash_input_lc = meta.advice_column();
        let code_length = meta.advice_column();
        let byte_push_size = meta.advice_column();
        let is_final = meta.advice_column();
        let padding = meta.advice_column();
        let push_rindex_inv = meta.advice_column();
        let length_inv = meta.advice_column();
        let push_table = array_init::array_init(|_| meta.fixed_column());
        let field_table = FieldTable::construct(meta);

        let is_field_border = field_table.is_field_border;

        // A byte is an opcode when `push_rindex == 0` on the previous row,
        // else it's push data.
        let push_rindex_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                // Conditions:
                // - Not on the first row
                meta.query_fixed(q_enable, Rotation::cur())
                    * not::expr(meta.query_fixed(q_first, Rotation::cur()))
            },
            |meta| meta.query_advice(push_rindex, Rotation::prev()),
            push_rindex_inv,
        );

        // Does the current row have bytecode field tag == Length?
        let is_row_tag_length = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                not::expr(meta.query_advice(padding, Rotation::cur())),
                not::expr(meta.query_advice(bytecode_table.tag, Rotation::cur())),
            ])
        };

        // Does the current row have bytecode field tag == Byte?
        let is_row_tag_byte = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                not::expr(meta.query_advice(padding, Rotation::cur())),
                meta.query_advice(bytecode_table.tag, Rotation::cur()),
            ])
        };

        // For a row tagged Length, is the length (value) zero?
        let length_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()) * is_row_tag_length(meta),
            |meta| meta.query_advice(value, Rotation::cur()),
            length_inv,
        );

        let q_continue = |meta: &mut VirtualCells<F>| {
            // When
            // - Not on the first row
            // - The previous row did not contain the last byte
            and::expr(vec![
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
                not::expr(meta.query_advice(is_final, Rotation::prev())),
            ])
        };
        

        meta.create_gate("continue", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Did the previous row have bytecode field tag == Length?
            let is_prev_row_tag_length = |meta: &mut VirtualCells<F>| {
                and::expr(vec![
                    not::expr(meta.query_fixed(q_first, Rotation::cur())),
                    not::expr(meta.query_advice(padding, Rotation::prev())),
                    not::expr(meta.query_advice(bytecode_table.tag, Rotation::prev())),
                ])
            };

            cb.require_equal(
                "if prev_row.tag == Length: index == 0 else index == index + 1",
                meta.query_advice(bytecode_table.index, Rotation::cur()),
                select::expr(
                    is_prev_row_tag_length(meta),
                    0.expr(),
                    meta.query_advice(bytecode_table.index, Rotation::prev()) + 1.expr(),
                ),
            );
            cb.require_equal(
                "is_code := push_rindex_prev == 0",
                meta.query_advice(bytecode_table.is_code, Rotation::cur()),
                select::expr(
                    is_prev_row_tag_length(meta),
                    1.expr(),
                    push_rindex_is_zero.clone().is_zero_expression,
                ),
            );
            cb.require_equal(
                "hash_input_lc = byte if is_field_border == true else hash_input_lc_prev * 256 + byte",
                meta.query_advice(hash_input_lc, Rotation::cur()),
                select::expr(
                    meta.query_advice(is_field_border, Rotation::cur()),
                    meta.query_advice(value, Rotation::cur()),
                    meta.query_advice(hash_input_lc, Rotation::prev()) * 256.expr()
                    + meta.query_advice(value, Rotation::cur())
                ),
            );            
            cb.require_equal(
                "code_hash needs to remain the same",
                meta.query_advice(bytecode_table.code_hash, Rotation::cur()),
                meta.query_advice(bytecode_table.code_hash, Rotation::prev()),
            );
            cb.require_equal(
                "code_length needs to remain the same",
                meta.query_advice(code_length, Rotation::cur()),
                meta.query_advice(code_length, Rotation::prev()),
            );
            cb.require_equal(
                "padding needs to remain the same",
                meta.query_advice(padding, Rotation::cur()),
                meta.query_advice(padding, Rotation::prev()),
            );

            // Conditions:
            // - Continuing
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                q_continue(meta),
            ]))
        });

        meta.create_gate("start of bytecode", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "next_row.tag == (tag.Length or tag.Padding) if length == 0 else tag.Byte",
                meta.query_advice(bytecode_table.tag, Rotation::next()),
                select::expr(
                    length_is_zero.clone().is_zero_expression,
                    select::expr(
                        meta.query_advice(padding, Rotation::next()),
                        BytecodeFieldTag::Padding.expr(),
                        BytecodeFieldTag::Length.expr(),
                    ),
                    BytecodeFieldTag::Byte.expr(),
                ),
            );
            cb.require_equal(
                "if row.tag == tag.Length: value == row.code_length",
                meta.query_advice(value, Rotation::cur()),
                meta.query_advice(code_length, Rotation::cur()),
            );

            // FIXME: Since randomness is only known at synthesis time, the RLC of empty
            // code_hash is not constant.  Consider doing a lookup to the empty code_hash
            // value? cb.condition(length_is_zero.clone().is_zero_expression,
            // |cb| {     cb.require_equal(
            //         "if length == 0: code_hash == RLC(EMPTY_HASH, randomness)",
            //         meta.query_advice(bytecode_table.code_hash, Rotation::cur()),
            //         Expression::Constant(keccak(&[], randomness)),
            //     );
            // });

            // Conditions:
            // - Not Continuing
            // - This is the start of a new bytecode
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                is_row_tag_length(meta),
                not::expr(q_continue(meta)),
            ]))
        });

        meta.create_gate("start of padding", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "row needs to be marked as padding",
                meta.query_advice(padding, Rotation::cur()),
                1.expr(),
            );
            // Conditions:
            // - Not Continuing
            // - This is not the start of a new bytecode
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(is_row_tag_length(meta)),
                not::expr(q_continue(meta)),
            ]))
        });

        meta.create_gate("length needs to be correct", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.condition(1.expr() - length_is_zero.clone().is_zero_expression, |cb| {
                cb.require_equal(
                    "index + 1 needs to equal code_length",
                    meta.query_advice(bytecode_table.index, Rotation::cur()) + 1.expr(),
                    meta.query_advice(code_length, Rotation::cur()),
                );
            });
            // Conditions:
            // - On the row with the last byte (`is_final == 1`)
            // - Of bytecode with length > 0
            // - Not padding
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_final, Rotation::cur()),
                not::expr(meta.query_advice(padding, Rotation::cur())),
            ]))
        });

        // Does the current row have bytecode field tag == Length?
        let q_byte_in_field_not_last = |meta: &mut VirtualCells<F>| {
            ((HASHBLOCK_BYTES_IN_FIELD-1).expr() - meta.query_advice(field_table.bytes_in_field_index, Rotation::cur()))
            * meta.query_advice(field_table.bytes_in_field_inv, Rotation::cur())
        };        

        let q_field_not_last = |meta: &mut VirtualCells<F>| {
            ((PoseidonHashTable::WIDTH-1).expr() - meta.query_advice(field_table.field_index, Rotation::cur()))
            * meta.query_advice(field_table.field_index_inv, Rotation::cur())
        };

        meta.create_gate("always", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_boolean(
                "is_final needs to be boolean",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.require_boolean(
                "padding needs to be boolean",
                meta.query_advice(padding, Rotation::cur()),
            );
            cb.condition(is_row_tag_byte(meta), |cb| {
                cb.require_equal(
                    "push_rindex := is_code ? byte_push_size : push_rindex_prev - 1",
                    meta.query_advice(push_rindex, Rotation::cur()),
                    select::expr(
                        meta.query_advice(bytecode_table.is_code, Rotation::cur()),
                        meta.query_advice(byte_push_size, Rotation::cur()),
                        meta.query_advice(push_rindex, Rotation::prev()) - 1.expr(),
                    ),
                );
            });
            // field table
            cb.require_boolean(
                "is_field_border needs to be boolean",
                meta.query_advice(field_table.is_field_border, Rotation::cur()),
            );

            cb.require_boolean(
                "query for byte_in_field_index_is_not_last needs to be boolean",
                q_byte_in_field_not_last(meta),
            );

            cb.require_boolean(
                "query for hash_field_index_is_not_last needs to be boolean",
                q_field_not_last(meta),
            );            

            // Conditions: Always
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("field table cycling", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let bytes_in_field_index = (HASHBLOCK_BYTES_IN_FIELD-1).expr() - meta.query_advice(field_table.bytes_in_field_index, Rotation::cur());
            cb.condition(bytes_in_field_index.clone(), |cb|{
                cb.require_equal(
                    "query for byte_in_field_index must 1 except for last",
                    q_byte_in_field_not_last(meta),
                    1.expr(),
                );    
            });

            cb.require_equal(
                "byte_in_field_index_next := if last 0 else byte_in_field_index + 1",
                meta.query_advice(field_table.bytes_in_field_index, Rotation::next()),
                select::expr(
                    q_byte_in_field_not_last(meta),
                    meta.query_advice(field_table.bytes_in_field_index, Rotation::cur()) + 1.expr(),
                    0.expr(),
                )
            );             

            cb.require_equal("is_field_border := bytes_in_field_index is zero", 
                meta.query_advice(field_table.is_field_border, Rotation::cur()),
                1.expr() - q_byte_in_field_not_last(meta),
            );            

            let field_index = (PoseidonHashTable::WIDTH-1).expr() - meta.query_advice(field_table.field_index, Rotation::cur());
            cb.condition(field_index, |cb|{
                cb.require_equal(
                    "query for hash_field_index must be 1 except for last",
                    q_field_not_last(meta),
                    1.expr(),
                );    
            });

            cb.require_equal(
                "hash_field_index_next := if is_byte_in_field_border (if is_field_last 0 else byte_in_field_index + 1 ) else byte_in_field_index",
                meta.query_advice(field_table.field_index, Rotation::next()),
                select::expr(
                    meta.query_advice(field_table.is_field_border, Rotation::cur()),
                    select::expr(
                        q_field_not_last(meta),
                        meta.query_advice(field_table.field_index, Rotation::cur()) + 1.expr(),
                        0.expr(),
                    ),
                    meta.query_advice(field_table.field_index, Rotation::cur())
                )
            );

            // Conditions:
            // - Byte tag
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                is_row_tag_byte(meta),
            ]))            
        });

        meta.create_gate("field table blanking", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "byte_in_field_index must be zero",
                meta.query_advice(field_table.bytes_in_field_index, Rotation::cur()),
                0.expr(),
            );

            cb.require_equal(
                "field_index must be zero",
                meta.query_advice(field_table.field_index, Rotation::cur()),
                0.expr(),
            );            

            cb.require_equal(
                "not field_border",
                meta.query_advice(field_table.is_field_border, Rotation::cur()),
                0.expr(),
            );

            // Conditions:
            // - not Byte tag
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(is_row_tag_byte(meta)),
            ]))            
        });

        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_boolean(
                "padding can only go 0 -> 1 once",
                meta.query_advice(padding, Rotation::cur())
                    - meta.query_advice(padding, Rotation::prev()),
            );

            cb.require_equal("is_field_border := false", 
                meta.query_advice(field_table.is_field_border, Rotation::cur()),
                0.expr(),
            );

            // Conditions:
            // - Not on the first row
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
            ]))
        });

        // The code_hash is checked on the latest row because only then have
        // we accumulated all the bytes. We also have to go through the bytes
        // in a forward manner because that's the only way we can know which
        // bytes are op codes and which are push data.
        meta.create_gate("last row", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "padding needs to be enabled OR the last row needs to be the last byte",
                or::expr(vec![
                    meta.query_advice(padding, Rotation::cur()),
                    meta.query_advice(is_final, Rotation::cur()),
                ]),
                1.expr(),
            );
            // Conditions:
            // - On the last row
            cb.gate(meta.query_selector(q_last))
        });

        // Lookup how many bytes the current opcode pushes
        // (also indirectly range checks `byte` to be in [0, 255])
        meta.lookup_any("Range bytes", |meta| {
            // Conditions: Always
            let q_enable = meta.query_fixed(q_enable, Rotation::cur()) * is_row_tag_byte(meta);
            let lookup_columns = vec![value, byte_push_size];
            let mut constraints = vec![];
            for i in 0..PUSH_TABLE_WIDTH {
                constraints.push((
                    q_enable.clone() * meta.query_advice(lookup_columns[i], Rotation::cur()),
                    meta.query_fixed(push_table[i], Rotation::cur()),
                ))
            }
            constraints
        });

        let lookup_columns = vec![hash_input_lc, field_table.control_length, bytecode_table.code_hash];
        // poseidon lookup, hash `WIDTH` lookups
        for i in 0..PoseidonHashTable::WIDTH {
            
            meta.lookup_any("poseidon", |meta| {
                // Conditions:
                // - On the border of each field (`field_table.is_field_border == 1`)
                // - the field_table.field_index match current i
                let enable = and::expr(vec![
                    meta.query_advice(field_table.is_field_border, Rotation::cur()),
                    field_table.field_selector::<_, {PoseidonHashTable::WIDTH}>(meta, i),
                ]);
                let mut constraints = Vec::new();

                // the first WIDTH cols in hash_table is input fields and we only pick the ith one
                for ((_, column), lookup_col) in hash_table.columns().iter().enumerate()
                    .filter(|(i_inp, _)|{*i_inp == i || *i_inp >= PoseidonHashTable::WIDTH})
                    .zip(lookup_columns.clone())
                {
                    constraints.push((
                        enable.clone() * meta.query_advice(lookup_col, Rotation::cur()),
                        meta.query_advice(*column, Rotation::cur()),
                    ))
                }
                // sanity check
                assert_eq!(constraints.len(), lookup_columns.len());
                constraints
            });
        }

        Config {
            minimum_rows: meta.minimum_rows(),
            q_enable,
            q_first,
            q_last,
            bytecode_table,
            field_table,
            push_rindex,
            hash_input_lc,
            code_length,
            byte_push_size,
            is_final,
            padding,
            push_rindex_inv,
            push_rindex_is_zero,
            length_inv,
            length_is_zero,
            push_table,
            hash_table,
        }
    }

    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        size: usize,
        witness: &[UnrolledBytecode<F>],
        _randomness: F,
    ) -> Result<(), Error> {
        self.assign_internal(layouter, size, witness, true)
    }

    pub(crate) fn assign_internal(
        &self,
        layouter: &mut impl Layouter<F>,
        size: usize,
        witness: &[UnrolledBytecode<F>],
        fail_fast: bool,
    ) -> Result<(), Error> {
        let push_rindex_is_zero_chip = IsZeroChip::construct(self.push_rindex_is_zero.clone());
        let length_is_zero_chip = IsZeroChip::construct(self.length_is_zero.clone());

        // Subtract the unusable rows from the size
        let last_row_offset = size - self.minimum_rows + 1;

        layouter.assign_region(
            || "assign bytecode",
            |mut region| {
                let mut offset = 0;
                let mut push_rindex_prev = 0;
                for bytecode in witness.iter() {
                    // Run over all the bytes
                    let mut push_rindex = 0;
                    let mut byte_push_size = 0;
                    let mut hash_input_lc = F::zero();
                    let code_length = F::from(bytecode.bytes.len() as u64);
                    for (idx, row) in bytecode.rows.iter().enumerate() {
                        if fail_fast && offset > last_row_offset {
                            log::error!(
                                "Bytecode Circuit: offset={} > last_row_offset={}",
                                offset,
                                last_row_offset
                            );
                            return Err(Error::Synthesis);
                        }

                        // Track which byte is an opcode and which is push
                        // data
                        let is_code = push_rindex == 0;
                        if idx > 0 {
                            byte_push_size = get_push_size(row.value.get_lower_128() as u8);
                            push_rindex = if is_code {
                                byte_push_size
                            } else {
                                push_rindex - 1
                            };

                            if idx % HASHBLOCK_BYTES_IN_FIELD == 0 {
                                hash_input_lc = F::zero();
                            } 
                            hash_input_lc = hash_input_lc * F::from(256u64) + row.value;
                        }

                        // Set the data for this row
                        if offset <= last_row_offset {
                            self.set_row(
                                &mut region,
                                &push_rindex_is_zero_chip,
                                &length_is_zero_chip,
                                offset,
                                true,
                                offset == last_row_offset,
                                row.code_hash,
                                row.tag,
                                row.index,
                                row.is_code,
                                row.value,
                                push_rindex,
                                hash_input_lc,
                                code_length,
                                F::from(byte_push_size as u64),
                                idx == bytecode.bytes.len(),
                                false,
                                F::from(push_rindex_prev),
                            )?;

                            push_rindex_prev = push_rindex;

                            // also field table
                            if row.tag == F::from(BytecodeFieldTag::Byte as u64) {
                                self.field_table.assign_row::<_, {PoseidonHashTable::WIDTH}>(&mut region, offset, (idx, bytecode.bytes.len() - idx))?;
                            }else {
                                self.field_table.assign_blank_row::<_, {PoseidonHashTable::WIDTH}>(&mut region, offset)?;
                            }                            

                            offset += 1;
                        }
                    }
                }

                // Padding
                for idx in offset..=last_row_offset {
                    self.set_row(
                        &mut region,
                        &push_rindex_is_zero_chip,
                        &length_is_zero_chip,
                        idx,
                        idx < last_row_offset,
                        idx == last_row_offset,
                        F::zero(),
                        F::from(BytecodeFieldTag::Padding as u64),
                        F::zero(),
                        F::one(),
                        F::zero(),
                        0,
                        F::zero(),
                        F::zero(),
                        F::zero(),
                        true,
                        true,
                        F::from(push_rindex_prev),
                    )?;
                    self.field_table.assign_blank_row::<_, {PoseidonHashTable::WIDTH}>(&mut region, offset)?;
                    push_rindex_prev = 0;
                }
                Ok(())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn set_row(
        &self,
        region: &mut Region<'_, F>,
        push_rindex_is_zero_chip: &IsZeroChip<F>,
        length_is_zero_chip: &IsZeroChip<F>,
        offset: usize,
        enable: bool,
        last: bool,
        code_hash: F,
        tag: F,
        index: F,
        is_code: F,
        value: F,
        push_rindex: u64,
        hash_input_lc: F,
        code_length: F,
        byte_push_size: F,
        is_final: bool,
        padding: bool,
        push_rindex_prev: F,
    ) -> Result<(), Error> {
        // q_enable
        region.assign_fixed(
            || format!("assign q_enable {}", offset),
            self.q_enable,
            offset,
            || Value::known(F::from(enable as u64)),
        )?;

        // q_first
        region.assign_fixed(
            || format!("assign q_first {}", offset),
            self.q_first,
            offset,
            || Value::known(F::from((offset == 0) as u64)),
        )?;

        // q_last
        if last {
            self.q_last.enable(region, offset)?;
        }

        // Advices
        for (name, column, value) in &[
            ("code_hash", self.bytecode_table.code_hash, code_hash),
            ("tag", self.bytecode_table.tag, tag),
            ("index", self.bytecode_table.index, index),
            ("is_code", self.bytecode_table.is_code, is_code),
            ("value", self.bytecode_table.value, value),
            ("push_rindex", self.push_rindex, F::from(push_rindex)),
            ("hash_input_lc", self.hash_input_lc, hash_input_lc),
            ("code_length", self.code_length, code_length),
            ("byte_push_size", self.byte_push_size, byte_push_size),
            ("is_final", self.is_final, F::from(is_final as u64)),
            ("padding", self.padding, F::from(padding as u64)),
        ] {
            region.assign_advice(
                || format!("assign {} {}", name, offset),
                *column,
                offset,
                || Value::known(*value),
            )?;
        }

        // push_rindex_is_zero_chip
        push_rindex_is_zero_chip.assign(region, offset, Value::known(push_rindex_prev))?;

        // length_is_zero chip
        length_is_zero_chip.assign(region, offset, Value::known(code_length))?;

        Ok(())
    }

    /// load fixed tables
    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        // push table: BYTE -> NUM_PUSHED:
        // [0, OpcodeId::PUSH1] -> 0
        // [OpcodeId::PUSH1, OpcodeId::PUSH32] -> [1..32]
        // [OpcodeId::PUSH32, 256] -> 0
        layouter.assign_region(
            || "push table",
            |mut region| {
                for byte in 0usize..256 {
                    let push_size = get_push_size(byte as u8);
                    for (name, column, value) in &[
                        ("byte", self.push_table[0], byte as u64),
                        ("push_size", self.push_table[1], push_size),
                    ] {
                        region.assign_fixed(
                            || format!("Push table assign {} {}", name, byte),
                            *column,
                            byte,
                            || Value::known(F::from(*value)),
                        )?;
                    }
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

/// Get unrolled bytecode from raw bytes
pub fn unroll<F: Field>(bytes: Vec<u8>, randomness: F) -> UnrolledBytecode<F> {
    let code_hash = keccak(&bytes[..], randomness);
    let mut rows = vec![BytecodeRow::<F> {
        code_hash,
        tag: F::from(BytecodeFieldTag::Length as u64),
        index: F::zero(),
        is_code: F::zero(),
        value: F::from(bytes.len() as u64),
    }];
    // Run over all the bytes
    let mut push_rindex = 0;
    for (index, byte) in bytes.iter().enumerate() {
        // Track which byte is an opcode and which is push data
        let is_code = push_rindex == 0;
        push_rindex = if is_code {
            get_push_size(*byte)
        } else {
            push_rindex - 1
        };

        rows.push(BytecodeRow::<F> {
            code_hash,
            tag: F::from(BytecodeFieldTag::Byte as u64),
            index: F::from(index as u64),
            is_code: F::from(is_code as u64),
            value: F::from(*byte as u64),
        });
    }
    UnrolledBytecode { bytes, rows }
}

fn is_push(byte: u8) -> bool {
    OpcodeId::PUSH1.as_u8() <= byte && byte <= OpcodeId::PUSH32.as_u8()
}

fn get_push_size(byte: u8) -> u64 {
    if is_push(byte) {
        byte as u64 - OpcodeId::PUSH1.as_u64() + 1
    } else {
        0u64
    }
}

fn keccak<F: Field>(msg: &[u8], randomness: F) -> F {
    let mut keccak = Keccak::default();
    keccak.update(msg);
    RandomLinearCombination::<F, 32>::random_linear_combine(
        Word::from_big_endian(keccak.digest().as_slice()).to_le_bytes(),
        randomness,
    )
}

fn into_words(message: &[u8]) -> Vec<u64> {
    let words_total = message.len() / 8;
    let mut words: Vec<u64> = vec![0; words_total];

    for i in 0..words_total {
        let mut word_bits: [u8; 8] = Default::default();
        word_bits.copy_from_slice(&message[i * 8..i * 8 + 8]);
        words[i] = u64::from_le_bytes(word_bits);
    }

    words
}

/// test module
#[cfg(any(feature = "test", test))]
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{bytecode_circuit::dev::test_bytecode_circuit_unrolled, util::DEFAULT_RAND};
    use eth_types::Bytecode;
    use halo2_proofs::halo2curves::bn256::Fr;

    /// get randomness value
    pub fn get_randomness<F: Field>() -> F {
        F::from(DEFAULT_RAND as u64)
    }

    /// Verify unrolling code
    #[test]
    fn bytecode_unrolling() {
        let k = 10;
        let randomness = get_randomness();
        let mut rows = vec![];
        let mut bytecode = Bytecode::default();
        // First add all non-push bytes, which should all be seen as code
        for byte in 0u8..=255u8 {
            if !is_push(byte) {
                bytecode.write(byte, true);
                rows.push(BytecodeRow {
                    code_hash: Fr::zero(),
                    tag: Fr::from(BytecodeFieldTag::Byte as u64),
                    index: Fr::from(rows.len() as u64),
                    is_code: Fr::from(true as u64),
                    value: Fr::from(byte as u64),
                });
            }
        }
        // Now add the different push ops
        for n in 1..=32 {
            let data_byte = OpcodeId::PUSH32.as_u8();
            bytecode.push(n, Word::from_little_endian(&vec![data_byte; n][..]));
            rows.push(BytecodeRow {
                code_hash: Fr::zero(),
                tag: Fr::from(BytecodeFieldTag::Byte as u64),
                index: Fr::from(rows.len() as u64),
                is_code: Fr::from(true as u64),
                value: Fr::from(OpcodeId::PUSH1.as_u64() + ((n - 1) as u64)),
            });
            for _ in 0..n {
                rows.push(BytecodeRow {
                    code_hash: Fr::zero(),
                    tag: Fr::from(BytecodeFieldTag::Byte as u64),
                    index: Fr::from(rows.len() as u64),
                    is_code: Fr::from(false as u64),
                    value: Fr::from(data_byte as u64),
                });
            }
        }
        // Set the code_hash of the complete bytecode in the rows
        let code_hash = keccak(&bytecode.to_vec()[..], randomness);
        for row in rows.iter_mut() {
            row.code_hash = code_hash;
        }
        rows.insert(
            0,
            BytecodeRow {
                code_hash,
                tag: Fr::from(BytecodeFieldTag::Length as u64),
                index: Fr::zero(),
                is_code: Fr::zero(),
                value: Fr::from(bytecode.to_vec().len() as u64),
            },
        );
        // Unroll the bytecode
        let unrolled = unroll(bytecode.to_vec(), randomness);
        // Check if the bytecode was unrolled correctly
        assert_eq!(
            UnrolledBytecode {
                bytes: bytecode.to_vec(),
                rows,
            },
            unrolled,
        );
        // Verify the unrolling in the circuit
        test_bytecode_circuit_unrolled(k, vec![unrolled], randomness, true);
    }

    /// Tests a fully empty circuit
    #[test]
    fn bytecode_empty() {
        let k = 9;
        let randomness: Fr = get_randomness();
        test_bytecode_circuit_unrolled(k, vec![unroll(vec![], randomness)], randomness, true);
    }

    #[test]
    fn bytecode_simple() {
        let k = 9;
        let randomness: Fr = get_randomness();
        let bytecodes = vec![
            unroll(vec![7u8], randomness),
            unroll(vec![6u8], randomness),
            unroll(vec![5u8], randomness),
        ];
        test_bytecode_circuit_unrolled(k, bytecodes, randomness, true);
    }

    /// Tests a fully full circuit
    #[test]
    fn bytecode_full() {
        let k = 9;
        let randomness: Fr = get_randomness();
        test_bytecode_circuit_unrolled(
            k,
            vec![unroll(vec![7u8; 2usize.pow(k) - 7], randomness)],
            randomness,
            true,
        );
    }

    /// Tests a circuit with incomplete bytecode
    #[test]
    fn bytecode_incomplete() {
        let k = 9;
        let randomness: Fr = get_randomness();
        test_bytecode_circuit_unrolled(
            k,
            vec![unroll(vec![7u8; 2usize.pow(k) + 1], randomness)],
            randomness,
            false,
        );
    }

    /// Tests multiple bytecodes in a single circuit
    #[test]
    fn bytecode_push() {
        let k = 9;
        let randomness: Fr = get_randomness();
        test_bytecode_circuit_unrolled(
            k,
            vec![
                unroll(vec![], randomness),
                unroll(vec![OpcodeId::PUSH32.as_u8()], randomness),
                unroll(
                    vec![OpcodeId::PUSH32.as_u8(), OpcodeId::ADD.as_u8()],
                    randomness,
                ),
                unroll(
                    vec![OpcodeId::ADD.as_u8(), OpcodeId::PUSH32.as_u8()],
                    randomness,
                ),
                unroll(
                    vec![
                        OpcodeId::ADD.as_u8(),
                        OpcodeId::PUSH32.as_u8(),
                        OpcodeId::ADD.as_u8(),
                    ],
                    randomness,
                ),
            ],
            randomness,
            true,
        );
    }

    /// Test invalid code_hash data
    #[test]
    fn bytecode_invalid_hash_data() {
        let k = 9;
        let randomness = get_randomness();
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode, randomness);
        test_bytecode_circuit_unrolled(k, vec![unrolled.clone()], randomness, true);
        // Change the code_hash on the first position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[0].code_hash += Fr::from(1u64);
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
        // Change the code_hash on another position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[4].code_hash += Fr::from(1u64);
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
        // Change all the hashes so it doesn't match the keccak lookup code_hash
        {
            let mut invalid = unrolled;
            for row in invalid.rows.iter_mut() {
                row.code_hash = Fr::one();
            }
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
    }

    /// Test invalid index
    #[test]
    #[ignore]
    fn bytecode_invalid_index() {
        let k = 9;
        let randomness: Fr = get_randomness();
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode, randomness);
        test_bytecode_circuit_unrolled(k, vec![unrolled.clone()], randomness, true);
        // Start the index at 1
        {
            let mut invalid = unrolled.clone();
            for row in invalid.rows.iter_mut() {
                row.index += Fr::one();
            }
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
        // Don't increment an index once
        {
            let mut invalid = unrolled;
            invalid.rows.last_mut().unwrap().index -= Fr::one();
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
    }

    /// Test invalid byte data
    #[test]
    fn bytecode_invalid_byte_data() {
        let k = 9;
        let randomness = get_randomness();
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode, randomness);
        test_bytecode_circuit_unrolled(k, vec![unrolled.clone()], randomness, true);
        // Change the first byte
        {
            let mut invalid = unrolled.clone();
            invalid.rows[1].value = Fr::from(9u64);
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
        // Change a byte on another position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[5].value = Fr::from(6u64);
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
        // Set a byte value out of range
        {
            let mut invalid = unrolled;
            invalid.rows[3].value = Fr::from(256u64);
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
    }

    /// Test invalid is_code data
    #[test]
    fn bytecode_invalid_is_code() {
        let k = 9;
        let randomness = get_randomness();
        let bytecode = vec![
            OpcodeId::ADD.as_u8(),
            OpcodeId::PUSH1.as_u8(),
            OpcodeId::PUSH1.as_u8(),
            OpcodeId::SUB.as_u8(),
            OpcodeId::PUSH7.as_u8(),
            OpcodeId::ADD.as_u8(),
            OpcodeId::PUSH6.as_u8(),
        ];
        let unrolled = unroll(bytecode, randomness);
        test_bytecode_circuit_unrolled(k, vec![unrolled.clone()], randomness, true);
        // Mark the 3rd byte as code (is push data from the first PUSH1)
        {
            let mut invalid = unrolled.clone();
            invalid.rows[3].is_code = Fr::one();
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
        // Mark the 4rd byte as data (is code)
        {
            let mut invalid = unrolled.clone();
            invalid.rows[4].is_code = Fr::zero();
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
        // Mark the 7th byte as code (is data for the PUSH7)
        {
            let mut invalid = unrolled;
            invalid.rows[7].is_code = Fr::one();
            test_bytecode_circuit_unrolled(k, vec![invalid], randomness, false);
        }
    }
}
