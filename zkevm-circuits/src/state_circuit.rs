//! The state circuit implementation.
mod constraint_builder;
mod lexicographic_ordering;
mod lookups;
mod multiple_precision_integer;
mod random_linear_combination;
#[cfg(test)]
mod test;

use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        util::RandomLinearCombination,
        witness::{Rw, RwMap, RwRow},
    },
    rw_table::RwTable,
};
use constraint_builder::{ConstraintBuilder, Queries};
use eth_types::{Address, Field, ToLittleEndian};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, VirtualCells},
    poly::Rotation,
};
use lexicographic_ordering::{
    Chip as LexicographicOrderingChip, Config as LexicographicOrderingConfig,
};
use lookups::{Chip as LookupsChip, Config as LookupsConfig, Queries as LookupsQueries};
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig, Queries as MpiQueries};
use random_linear_combination::{Chip as RlcChip, Config as RlcConfig, Queries as RlcQueries};
#[cfg(test)]
use std::collections::HashMap;

const N_LIMBS_RW_COUNTER: usize = 2;
const N_LIMBS_ACCOUNT_ADDRESS: usize = 10;
const N_LIMBS_ID: usize = 2;

/// Config for StateCircuit
#[derive(Clone)]
pub struct StateConfig<F: Field> {
    // Figure out why you get errors when this is Selector.
    // https://github.com/appliedzkp/zkevm-circuits/issues/407
    selector: Column<Fixed>,

    rw_table: RwTable,

    rw_counter_mpi: MpiConfig<u32, N_LIMBS_RW_COUNTER>,
    //is_write: Column<Advice>,
    //tag: Column<Advice>,
    id_mpi: MpiConfig<u32, N_LIMBS_ID>,
    address_mpi: MpiConfig<Address, N_LIMBS_ACCOUNT_ADDRESS>,
    //field_tag: Column<Advice>,
    storage_key_rlc: RlcConfig<N_BYTES_WORD>,
    //value: Column<Advice>,
    is_id_unchanged: IsZeroConfig<F>,
    is_storage_key_unchanged: IsZeroConfig<F>,

    lookups: LookupsConfig,
    power_of_randomness: [Column<Instance>; N_BYTES_WORD - 1],
    lexicographic_ordering: LexicographicOrderingConfig<F>,
}

type Lookup<F> = (&'static str, Expression<F>, Expression<F>);

/// State Circuit for proving RwTable is valid
#[derive(Default)]
pub struct StateCircuit<F: Field> {
    pub(crate) randomness: F,
    // use rows rather than RwMap here mainly for testing
    pub(crate) rows: Vec<RwRow<F>>,
    #[cfg(test)]
    overrides: HashMap<(test::AdviceColumn, usize), F>,
}

impl<F: Field> StateCircuit<F> {
    /// make a new state circuit from an RwMap
    pub fn new(randomness: F, rw_map: RwMap) -> Self {
        let rows = rw_map.table_assignments(randomness);
        Self {
            randomness,
            rows,
            #[cfg(test)]
            overrides: HashMap::new(),
            //#[cfg(test)]
           // colid_map: colid_map,
        }
    }

    /// powers of randomness for instance columns
    pub fn instance(&self) -> Vec<Vec<F>> {
        (1..32)
            .map(|exp| vec![self.randomness.pow(&[exp, 0, 0, 0]); self.rows.len()])
            .collect()
    }
    #[allow(clippy::too_many_arguments)]
    fn assign_row(
        &self,
        config: &StateConfig<F>,
        region: &mut Region<F>,
        is_storage_key_unchanged: &IsZeroChip<F>,
        is_id_unchanged: &IsZeroChip<F>,
        lexicographic_ordering_chip: &LexicographicOrderingChip<F>,
        offset: usize,
        row: RwRow<F>,
        prev_row: Option<RwRow<F>>,
    ) -> Result<(), Error> {
        region.assign_fixed(|| "selector", config.selector, offset, || Ok(F::one()))?;

        config
            .rw_table
            .assign_row(region, offset, self.randomness, &row)?;

        config
            .rw_counter_mpi
            .assign(region, offset, row.rw_counter as u32)?;
        config.id_mpi.assign(region, offset, row.id as u32)?;
        config.address_mpi.assign(region, offset, row.address)?;

        config
            .storage_key_rlc
            .assign(region, offset, self.randomness, row.storage_key)?;

        if offset != 0 {
            let rw_keys = row.rw_keys();
            let prev_rw_keys = prev_row
                .expect("prev_row is empty only for first row")
                .rw_keys();
            //println!("keys VS {:?} {:?}", rw_keys, prev_rw_keys);
            lexicographic_ordering_chip.assign(region, offset, &rw_keys, &prev_rw_keys)?;

            // assign storage key diff
            let cur_storage_key = RandomLinearCombination::random_linear_combine(
                row.storage_key.to_le_bytes(),
                self.randomness,
            );
            let prev_storage_key = RandomLinearCombination::random_linear_combine(
                prev_row.unwrap_or_default().storage_key.to_le_bytes(),
                self.randomness,
            );
            is_storage_key_unchanged.assign(
                region,
                offset,
                Some(cur_storage_key - prev_storage_key),
            )?;
            // assign id diff

            let id_change =
                F::from(row.id as u64) - F::from(prev_row.unwrap_or_default().id as u64);
            is_id_unchanged.assign(region, offset, Some(id_change))?;
            let _storage_key_change = RandomLinearCombination::random_linear_combine(
                row.storage_key.to_le_bytes(),
                self.randomness,
            ) - RandomLinearCombination::random_linear_combine(
                prev_row.unwrap_or_default().storage_key.to_le_bytes(),
                self.randomness,
            );
        }

        Ok(())
    }
}

impl<F: Field> Circuit<F> for StateCircuit<F> {
    type Config = StateConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let selector = meta.fixed_column();
        let lookups = LookupsChip::configure(meta);
        let power_of_randomness = [0; N_BYTES_WORD - 1].map(|_| meta.instance_column());

        let rw_table = RwTable::construct(meta);
        let is_storage_key_unchanged_column = meta.advice_column();
        let is_id_unchanged_column = meta.advice_column();
        let id_mpi = MpiChip::configure(meta, rw_table.id, selector);
        let address_mpi = MpiChip::configure(meta, rw_table.address, selector);
        let storage_key_rlc = RlcChip::configure(
            meta,
            selector,
            rw_table.storage_key,
            lookups.u8,
            power_of_randomness,
        );
        let rw_counter_mpi = MpiChip::configure(meta, rw_table.rw_counter, selector);

        let lexicographic_ordering = LexicographicOrderingChip::configure(
            meta,
            rw_table.tag,
            rw_table.field_tag,
            id_mpi.limbs,
            address_mpi.limbs,
            storage_key_rlc.bytes,
            rw_counter_mpi.limbs,
            rw_table,
            //lookups.u16,
        );

        let is_id_unchanged = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(lexicographic_ordering.selector, Rotation::cur()),
            |meta| {
                meta.query_advice(rw_table.id, Rotation::cur())
                    - meta.query_advice(rw_table.id, Rotation::prev())
            },
            is_id_unchanged_column,
        );
        let is_storage_key_unchanged = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(lexicographic_ordering.selector, Rotation::cur()),
            |meta| {
                meta.query_advice(rw_table.storage_key, Rotation::cur())
                    - meta.query_advice(rw_table.storage_key, Rotation::prev())
            },
            is_storage_key_unchanged_column,
        );

        let config = Self::Config {
            selector,
            address_mpi,
            id_mpi,
            rw_counter_mpi,
            storage_key_rlc,
            is_id_unchanged,
            lexicographic_ordering,
            is_storage_key_unchanged,
            lookups,
            power_of_randomness,
            rw_table,
        };

        let mut constraint_builder = ConstraintBuilder::new();
        meta.create_gate("state circuit constraints", |meta| {
            let queries = queries(meta, &config);
            constraint_builder.build(&queries);
            constraint_builder.gate(queries.selector)
        });
        for (name, expressions) in constraint_builder.lookups() {
            meta.lookup_any(name, |_| vec![expressions]);
        }

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        //println!("synthesize begin");
        LookupsChip::construct(config.lookups).load(&mut layouter)?;

        let is_id_unchanged = IsZeroChip::construct(config.is_id_unchanged.clone());
        let is_storage_key_unchanged =
            IsZeroChip::construct(config.is_storage_key_unchanged.clone());
        let lexicographic_ordering_chip =
            LexicographicOrderingChip::construct(config.lexicographic_ordering.clone());

        layouter.assign_region(
            || "rw table",
            |mut region| {
                let mut rows = self.rows.clone();

                rows.insert(0, Rw::Start.table_assignment(self.randomness));
                for (offset, row) in rows.iter().enumerate() {
                    println!("offset {} row {:#?}", offset, row);
                    self.assign_row(
                        &config,
                        &mut region,
                        &is_storage_key_unchanged,
                        &is_id_unchanged,
                        &lexicographic_ordering_chip,
                        offset,
                        *row,
                        if offset == 0 {
                            None
                        } else {
                            Some(rows[offset - 1])
                        },
                    )?;
                }

                #[cfg(test)]
                for ((column, offset), &f) in &self.overrides {
                    let advice_column = column.value(&config);
                    region.assign_advice(|| "override", advice_column, *offset, || Ok(f))?;
                }

                Ok(())
            },
        )
    }
}

fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: &StateConfig<F>) -> Queries<F> {
    Queries {
        selector: meta.query_fixed(c.selector, Rotation::cur()),
        rw_counter: MpiQueries::new(meta, c.rw_counter_mpi),
        is_write: meta.query_advice(c.rw_table.is_write, Rotation::cur()),
        tag: meta.query_advice(c.rw_table.tag, Rotation::cur()),
        prev_tag: meta.query_advice(c.rw_table.tag, Rotation::prev()),
        id: MpiQueries::new(meta, c.id_mpi),
        address: MpiQueries::new(meta, c.address_mpi),
        is_id_unchanged: c.is_id_unchanged.is_zero_expression.clone(),
        field_tag: meta.query_advice(c.rw_table.field_tag, Rotation::cur()),
        storage_key: RlcQueries::new(meta, c.storage_key_rlc),
        value: meta.query_advice(c.rw_table.value, Rotation::cur()),
        value_col_prev: meta.query_advice(c.rw_table.value, Rotation::prev()),
        value_prev: meta.query_advice(c.rw_table.value_prev, Rotation::cur()),
        lookups: LookupsQueries::new(meta, c.lookups),
        power_of_randomness: c
            .power_of_randomness
            .map(|c| meta.query_instance(c, Rotation::cur())),
        is_storage_key_unchanged: c.is_storage_key_unchanged.is_zero_expression.clone(),
        lexicographic_ordering_upper_limb_difference_is_zero: c
            .lexicographic_ordering
            .upper_limb_difference_is_zero
            .is_zero_expression
            .clone(),
    }
}
