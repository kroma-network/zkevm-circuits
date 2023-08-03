//! The state circuit implementation.
mod constraint_builder;
mod lexicographic_ordering;
mod lookups;
mod multiple_precision_integer;
mod random_linear_combination;
#[cfg(test)]
mod test;

use crate::{
    evm_circuit::{param::N_BYTES_WORD, util::rlc},
    table::{AccountFieldTag, LookupTable, MPTProofType, MptTable, RwTable, RwTableTag},
    util::{Challenges, Expr, SubCircuit, SubCircuitConfig},
    witness::{self, MptUpdates, Rw, RwMap},
};
use constraint_builder::{ConstraintBuilder, Queries};
use eth_types::{Address, Field, ToLittleEndian};
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
};
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use lexicographic_ordering::Config as LexicographicOrderingConfig;
use lookups::{Chip as LookupsChip, Config as LookupsConfig, Queries as LookupsQueries};
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig, Queries as MpiQueries};
use random_linear_combination::{Chip as RlcChip, Config as RlcConfig, Queries as RlcQueries};
#[cfg(test)]
use std::collections::HashMap;
use std::marker::PhantomData;

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use self::{
    constraint_builder::{MptUpdateTableQueries, RwTableQueries},
    lexicographic_ordering::LimbIndex,
};

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};

const N_LIMBS_RW_COUNTER: usize = 2;
const N_LIMBS_ACCOUNT_ADDRESS: usize = 10;
const N_LIMBS_ID: usize = 2;

/// Config for StateCircuit
#[derive(Clone)]
pub struct StateCircuitConfig<F> {
    // Figure out why you get errors when this is Selector.
    selector: Column<Fixed>,
    // https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/407
    rw_table: RwTable,
    sort_keys: SortKeysConfig,
    // Assigned value at the start of the block. For Rw::Account and
    // Rw::AccountStorage rows this is the committed value in the MPT, for
    // others, it is 0.
    initial_value: Column<Advice>,
    // For Rw::AccountStorage, identify non-existing if both committed value and
    // new value are zero. Will do lookup for MPTProofType::NonExistingStorageProof if
    // non-existing, otherwise do lookup for MPTProofType::StorageMod.
    is_non_exist: BatchedIsZeroConfig,
    // Intermediary witness used to reduce mpt lookup expression degree
    mpt_proof_type: Column<Advice>,
    state_root: Column<Advice>,
    lexicographic_ordering: LexicographicOrderingConfig,
    not_first_access: Column<Advice>,
    lookups: LookupsConfig,
    power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
    // External tables
    mpt_table: MptTable,
}

/// Circuit configuration arguments
pub struct StateCircuitConfigArgs<F: Field> {
    /// RwTable
    pub rw_table: RwTable,
    /// MptTable
    pub mpt_table: MptTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

/// Circuit exported cells after synthesis, used for subcircuit
#[derive(Clone, Debug)]
pub struct StateCircuitExports<V> {
    /// start state root
    pub start_state_root: (Cell, Value<V>),
    /// final state root
    pub end_state_root: (Cell, Value<V>),
}

impl<F: Field> SubCircuitConfig<F> for StateCircuitConfig<F> {
    type ConfigArgs = StateCircuitConfigArgs<F>;

    /// Return a new StateCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            rw_table,
            mpt_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let selector = meta.fixed_column();
        log::debug!("state circuit selector {:?}", selector);
        let lookups = LookupsChip::configure(meta);
        let power_of_randomness: [Expression<F>; 31] = challenges.evm_word_powers_of_randomness();

        let rw_counter = MpiChip::configure(meta, selector, rw_table.rw_counter, lookups);
        let tag = BinaryNumberChip::configure(meta, selector, Some(rw_table.tag.into()));
        let id = MpiChip::configure(meta, selector, rw_table.id, lookups);
        let address = MpiChip::configure(meta, selector, rw_table.address, lookups);

        let storage_key = RlcChip::configure(
            meta,
            selector,
            rw_table.storage_key,
            lookups,
            challenges.evm_word(),
        );

        let initial_value = meta.advice_column_in(SecondPhase);
        let is_non_exist = BatchedIsZeroChip::configure(
            meta,
            (SecondPhase, SecondPhase),
            |meta| meta.query_fixed(selector, Rotation::cur()),
            |meta| {
                [
                    meta.query_advice(rw_table.field_tag, Rotation::cur()),
                    meta.query_advice(initial_value, Rotation::cur()),
                    meta.query_advice(rw_table.value, Rotation::cur()),
                ]
            },
        );
        let mpt_proof_type = meta.advice_column_in(SecondPhase);
        let state_root = meta.advice_column_in(SecondPhase);
        meta.enable_equality(state_root);

        let sort_keys = SortKeysConfig {
            tag,
            id,
            field_tag: rw_table.field_tag,
            address,
            storage_key,
            rw_counter,
        };

        let lexicographic_ordering = LexicographicOrderingConfig::configure(
            meta,
            sort_keys,
            lookups,
            power_of_randomness.clone(),
        );

        // annotate columns
        rw_table.annotate_columns(meta);
        mpt_table.annotate_columns(meta);

        let config = Self {
            selector,
            sort_keys,
            initial_value,
            is_non_exist,
            mpt_proof_type,
            state_root,
            lexicographic_ordering,
            not_first_access: meta.advice_column(),
            lookups,
            power_of_randomness,
            rw_table,
            mpt_table,
        };

        let mut constraint_builder = ConstraintBuilder::new();
        meta.create_gate("state circuit constraints", |meta| {
            let queries = queries(meta, &config);
            constraint_builder.build(&queries);
            constraint_builder.gate(queries.selector)
        });
        for (name, lookup) in constraint_builder.lookups() {
            meta.lookup_any(name, |_| lookup);
        }

        config
    }
}

impl<F: Field> StateCircuitConfig<F> {
    /// load fixed tables
    pub(crate) fn load_aux_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        LookupsChip::construct(self.lookups).load(layouter)
    }

    /// Make the assignments to the StateCircuit
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        rows: &[Rw],
        updates: &MptUpdates,
        n_rows: usize, // 0 means dynamically calculated from `rows`.
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "state circuit",
            |mut region| {
                self.assign_with_region(&mut region, rows, updates, n_rows, challenges.evm_word())
            },
        )?;
        Ok(())
    }

    fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        rows: &[Rw],
        updates: &MptUpdates,
        n_rows: usize, // 0 means dynamically calculated from `rows`.
        randomness: Value<F>,
    ) -> Result<StateCircuitExports<Assigned<F>>, Error> {
        let tag_chip = BinaryNumberChip::construct(self.sort_keys.tag);

        let (rows, padding_length) = RwMap::table_assignments_prepad(rows, n_rows);
        log::info!(
            "state circuit assign total rows {}, n_rows {}, padding_length {}",
            rows.len(),
            n_rows,
            padding_length
        );
        let rows_len = rows.len();

        let mut state_root =
            randomness.map(|randomness| rlc::value(&updates.old_root().to_le_bytes(), randomness));

        let mut start_state_root: Option<AssignedCell<_, F>> = None;
        let mut end_state_root: Option<AssignedCell<_, F>> = None;
        // annotate columns
        self.annotate_circuit_in_region(region);

        for (offset, row) in rows.iter().enumerate() {
            if offset == 0 || offset + 1 >= padding_length {
                log::trace!("state circuit assign offset:{} row:{:?}", offset, row);
            }

            region.assign_fixed(
                || "selector",
                self.selector,
                offset,
                || Value::known(F::one()),
            )?;

            tag_chip.assign(region, offset, &row.tag())?;

            self.sort_keys
                .rw_counter
                .assign(region, offset, row.rw_counter() as u32)?;

            if let Some(id) = row.id() {
                self.sort_keys.id.assign(region, offset, id as u32)?;
            }

            if let Some(address) = row.address() {
                self.sort_keys.address.assign(region, offset, address)?;
            }

            if let Some(storage_key) = row.storage_key() {
                self.sort_keys
                    .storage_key
                    .assign(region, offset, randomness, storage_key)?;
            }

            if offset > 0 {
                let prev_row = &rows[offset - 1];
                let index = self
                    .lexicographic_ordering
                    .assign(region, offset, row, prev_row)?;
                let is_first_access =
                    !matches!(index, LimbIndex::RwCounter0 | LimbIndex::RwCounter1);

                region.assign_advice(
                    || "not_first_access",
                    self.not_first_access,
                    offset,
                    || Value::known(if is_first_access { F::zero() } else { F::one() }),
                )?;

                if is_first_access {
                    // If previous row was a last access, we need to update the state root.
                    state_root = randomness
                        .zip(state_root)
                        .map(|(randomness, mut state_root)| {
                            if let Some(update) = updates.get(prev_row) {
                                let (new_root, old_root) = update.root_assignments(randomness);
                                assert_eq!(state_root, old_root);
                                state_root = new_root;
                            }
                            if matches!(row.tag(), RwTableTag::CallContext)
                                && !row.is_write()
                                && row.value_assignment(randomness) != F::zero()
                            {
                                log::error!("invalid call context: {:?}", row);
                            }
                            state_root
                        });
                }
            }

            // The initial value can be determined from the mpt updates or is 0.
            let initial_value = randomness.map(|randomness| {
                updates
                    .get(row)
                    .map(|u| u.value_assignments(randomness).1)
                    .unwrap_or_default()
            });
            region.assign_advice(
                || "initial_value",
                self.initial_value,
                offset,
                || initial_value,
            )?;

            // Identify non-existing if both committed value and new value are zero.
            let is_non_exist_inputs = randomness.map(|randomness| {
                let (_, committed_value) = updates
                    .get(row)
                    .map(|u| u.value_assignments(randomness))
                    .unwrap_or_default();
                let value = row.value_assignment(randomness);
                [
                    F::from(row.field_tag().unwrap_or_default()),
                    committed_value,
                    value,
                ]
            });
            BatchedIsZeroChip::construct(self.is_non_exist.clone()).assign(
                region,
                offset,
                is_non_exist_inputs,
            )?;
            let mpt_proof_type = is_non_exist_inputs.map(|[_field_tag, committed_value, value]| {
                F::from(match row {
                    Rw::AccountStorage { .. } => {
                        if committed_value.is_zero_vartime() && value.is_zero_vartime() {
                            MPTProofType::NonExistingStorageProof as u64
                        } else {
                            MPTProofType::StorageMod as u64
                        }
                    }
                    Rw::Account { field_tag, .. } => {
                        if committed_value.is_zero_vartime()
                            && value.is_zero_vartime()
                            && matches!(field_tag, AccountFieldTag::CodeHash)
                        {
                            MPTProofType::NonExistingAccountProof as u64
                        } else {
                            *field_tag as u64
                        }
                    }
                    _ => 0,
                })
            });
            region.assign_advice(
                || "mpt_proof_type",
                self.mpt_proof_type,
                offset,
                || mpt_proof_type,
            )?;

            // TODO: Switch from Rw::Start -> Rw::Padding to simplify this logic.
            // State root assignment is at previous row (offset - 1) because the state root
            // changes on the last access row.
            if offset != 0 {
                let assigned = region.assign_advice(
                    || "state_root",
                    self.state_root,
                    offset - 1,
                    || state_root,
                )?;
                if start_state_root.is_none() {
                    start_state_root.replace(assigned);
                }
            }

            if offset + 1 == rows_len {
                // The last row is always a last access, so we need to handle the case where the
                // state root changes because of an mpt lookup on the last row.
                if let Some(update) = updates.get(row) {
                    state_root = randomness.zip(state_root).map(|(randomness, state_root)| {
                        let (new_root, old_root) = update.root_assignments(randomness);
                        if !state_root.is_zero_vartime() {
                            assert_eq!(state_root, old_root);
                        }
                        new_root
                    });
                }
                let assigned = region.assign_advice(
                    || "last row state_root",
                    self.state_root,
                    offset,
                    || state_root,
                )?;
                end_state_root.replace(assigned);
            }
        }

        let start_state_root = start_state_root.expect("should be assigned");
        let end_state_root = end_state_root.expect("should be assigned");
        Ok(StateCircuitExports {
            start_state_root: (start_state_root.cell(), start_state_root.value_field()),
            end_state_root: (end_state_root.cell(), end_state_root.value_field()),
        })
    }

    fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        self.rw_table.annotate_columns_in_region(region);
        self.mpt_table.annotate_columns_in_region(region);
        self.is_non_exist
            .annotate_columns_in_region(region, "STATE");
        self.lexicographic_ordering
            .annotate_columns_in_region(region, "STATE");
        self.sort_keys.annotate_columns_in_region(region, "STATE");
        region.name_column(|| "STATE_selector", self.selector);
        region.name_column(|| "STATE_not_first_access", self.not_first_access);
        region.name_column(|| "STATE_phase2_initial_value", self.initial_value);
        region.name_column(|| "STATE_phase2_mpt_proof_type", self.mpt_proof_type);
        region.name_column(|| "STATE_phase2_state_root", self.state_root);
    }
}

/// Keys for sorting the rows of the state circuit
#[derive(Clone, Copy)]
pub struct SortKeysConfig {
    tag: BinaryNumberConfig<RwTableTag, 4>,
    id: MpiConfig<u32, N_LIMBS_ID>,
    address: MpiConfig<Address, N_LIMBS_ACCOUNT_ADDRESS>,
    field_tag: Column<Advice>,
    storage_key: RlcConfig<N_BYTES_WORD>,
    rw_counter: MpiConfig<u32, N_LIMBS_RW_COUNTER>,
}

impl SortKeysConfig {
    /// Annotates this config within a circuit region.
    pub fn annotate_columns_in_region<F: Field>(&self, region: &mut Region<F>, prefix: &str) {
        self.tag.annotate_columns_in_region(region, prefix);
        self.address.annotate_columns_in_region(region, prefix);
        self.id.annotate_columns_in_region(region, prefix);
        self.storage_key.annotate_columns_in_region(region, prefix);
        self.rw_counter.annotate_columns_in_region(region, prefix);
        region.name_column(|| format!("{prefix}_field_tag"), self.field_tag);
    }
}

type Lookup<F> = (&'static str, Expression<F>, Expression<F>);

/// State Circuit for proving RwTable is valid
#[derive(Default, Clone, Debug)]
pub struct StateCircuit<F> {
    /// Rw rows
    pub rows: Vec<Rw>,
    pub(crate) updates: MptUpdates,
    pub(crate) n_rows: usize,
    pub(crate) exports: std::cell::RefCell<Option<StateCircuitExports<Assigned<F>>>>,
    #[cfg(test)]
    overrides: HashMap<(test::AdviceColumn, isize), F>,
    _marker: PhantomData<F>,
}

impl<F: Field> StateCircuit<F> {
    /// make a new state circuit from an RwMap
    pub fn new(rw_map: RwMap, n_rows: usize) -> Self {
        let rows = rw_map.table_assignments();
        log::warn!("build StateCircuit from mock MptUpdates");
        let updates = MptUpdates::from_rws_with_mock_state_roots(
            &rows,
            0xcafeu64.into(),
            0xdeadbeefu64.into(),
        );
        Self {
            rows,
            updates,
            exports: std::cell::RefCell::new(None),
            n_rows,
            #[cfg(test)]
            overrides: HashMap::new(),
            _marker: PhantomData::default(),
        }
    }
}

impl<F: Field> SubCircuit<F> for StateCircuit<F> {
    type Config = StateCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let rows = block.rws.table_assignments();
        let updates = block.mpt_updates.clone();
        Self {
            rows,
            updates,
            exports: std::cell::RefCell::new(None),
            n_rows: block.circuits_params.max_rws,
            #[cfg(test)]
            overrides: HashMap::new(),
            _marker: PhantomData::default(),
        }
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (
            block.rws.0.values().flatten().count() + 1,
            std::cmp::max(1 << 16, block.circuits_params.max_rws),
        )
    }

    /// Make the assignments to the StateCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_aux_tables(layouter)?;

        let randomness = challenges.evm_word();

        let mut is_first_time = true;

        // Assigning to same columns in different regions should be avoided.
        // Here we use one single region to assign `overrides` to both rw table and
        // other parts.
        layouter.assign_region(
            || "state circuit",
            |mut region| {
                if is_first_time {
                    is_first_time = false;
                    region.assign_advice(
                        || "step selector",
                        config.rw_table.rw_counter,
                        self.n_rows - 1,
                        || Value::known(F::zero()),
                    )?;
                    return Ok(());
                }
                config.rw_table.load_with_region(
                    &mut region,
                    &self.rows,
                    self.n_rows,
                    randomness,
                )?;

                let exports = config.assign_with_region(
                    &mut region,
                    &self.rows,
                    &self.updates,
                    self.n_rows,
                    randomness,
                )?;
                if self.exports.borrow().is_none() {
                    self.exports.borrow_mut().replace(exports);
                }

                #[cfg(test)]
                {
                    let padding_length = RwMap::padding_len(self.rows.len(), self.n_rows);
                    for ((column, row_offset), &f) in &self.overrides {
                        let advice_column = column.value(config);
                        let offset =
                            usize::try_from(isize::try_from(padding_length).unwrap() + *row_offset)
                                .unwrap();
                        region.assign_advice(
                            || "override",
                            advice_column,
                            offset,
                            || Value::known(f),
                        )?;
                    }
                }

                Ok(())
            },
        )
    }

    /// powers of randomness for instance columns
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
}

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
impl<F: Field> Circuit<F> for StateCircuit<F>
where
    F: Field,
{
    type Config = (StateCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rw_table = RwTable::construct(meta);
        let mpt_table = MptTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            StateCircuitConfig::new(
                meta,
                StateCircuitConfigArgs {
                    rw_table,
                    mpt_table,
                    challenges,
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        config
            .mpt_table
            .load(&mut layouter, &self.updates, challenges.evm_word())?;
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: &StateCircuitConfig<F>) -> Queries<F> {
    let first_different_limb = c.lexicographic_ordering.first_different_limb;
    let final_bits_sum = meta.query_advice(first_different_limb.bits[3], Rotation::cur())
        + meta.query_advice(first_different_limb.bits[4], Rotation::cur());
    let mpt_update_table_expressions = c.mpt_table.table_exprs(meta);

    Queries {
        selector: meta.query_fixed(c.selector, Rotation::cur()),
        // TODO: use LookupTable trait here.
        rw_table: RwTableQueries {
            rw_counter: meta.query_advice(c.rw_table.rw_counter, Rotation::cur()),
            prev_rw_counter: meta.query_advice(c.rw_table.rw_counter, Rotation::prev()),
            is_write: meta.query_advice(c.rw_table.is_write, Rotation::cur()),
            tag: meta.query_advice(c.rw_table.tag, Rotation::cur()),
            id: meta.query_advice(c.rw_table.id, Rotation::cur()),
            prev_id: meta.query_advice(c.rw_table.id, Rotation::prev()),
            address: meta.query_advice(c.rw_table.address, Rotation::cur()),
            prev_address: meta.query_advice(c.rw_table.address, Rotation::prev()),
            field_tag: meta.query_advice(c.rw_table.field_tag, Rotation::cur()),
            storage_key: meta.query_advice(c.rw_table.storage_key, Rotation::cur()),
            value: meta.query_advice(c.rw_table.value, Rotation::cur()),
            value_prev: meta.query_advice(c.rw_table.value, Rotation::prev()),
            value_prev_column: meta.query_advice(c.rw_table.value_prev, Rotation::cur()),
        },
        // TODO: clean this up
        mpt_update_table: MptUpdateTableQueries {
            address: mpt_update_table_expressions[0].clone(),
            storage_key: mpt_update_table_expressions[1].clone(),
            proof_type: mpt_update_table_expressions[2].clone(),
            new_root: mpt_update_table_expressions[3].clone(),
            old_root: mpt_update_table_expressions[4].clone(),
            new_value: mpt_update_table_expressions[5].clone(),
            old_value: mpt_update_table_expressions[6].clone(),
        },
        lexicographic_ordering_selector: meta
            .query_fixed(c.lexicographic_ordering.selector, Rotation::cur()),
        rw_counter: MpiQueries::new(meta, c.sort_keys.rw_counter),
        tag_bits: c
            .sort_keys
            .tag
            .bits
            .map(|bit| meta.query_advice(bit, Rotation::cur())),
        id: MpiQueries::new(meta, c.sort_keys.id),
        // this isn't binary! only 0 if most significant 3 bits are all 0 and at most 1 of the two
        // least significant bits is 1.
        // TODO: this can mask off just the top 3 bits if you want, since the 4th limb index is
        // Address9, which is always 0 for Rw::Stack rows.
        is_tag_and_id_unchanged: 4.expr()
            * (meta.query_advice(first_different_limb.bits[0], Rotation::cur())
                + meta.query_advice(first_different_limb.bits[1], Rotation::cur())
                + meta.query_advice(first_different_limb.bits[2], Rotation::cur()))
            + final_bits_sum.clone() * (1.expr() - final_bits_sum),
        address: MpiQueries::new(meta, c.sort_keys.address),
        storage_key: RlcQueries::new(meta, c.sort_keys.storage_key),
        value_prev_col: meta.query_advice(c.rw_table.value_prev, Rotation::cur()),
        initial_value: meta.query_advice(c.initial_value, Rotation::cur()),
        initial_value_prev: meta.query_advice(c.initial_value, Rotation::prev()),
        is_non_exist: meta.query_advice(c.is_non_exist.is_zero, Rotation::cur()),
        mpt_proof_type: meta.query_advice(c.mpt_proof_type, Rotation::cur()),
        lookups: LookupsQueries::new(meta, c.lookups),
        power_of_randomness: c.power_of_randomness.clone(),
        first_different_limb: [0, 1, 2, 3]
            .map(|idx| meta.query_advice(first_different_limb.bits[idx], Rotation::cur())),
        not_first_access: meta.query_advice(c.not_first_access, Rotation::cur()),
        last_access: 1.expr() - meta.query_advice(c.not_first_access, Rotation::next()),
        state_root: meta.query_advice(c.state_root, Rotation::cur()),
        state_root_prev: meta.query_advice(c.state_root, Rotation::prev()),
    }
}

#[cfg(test)]
mod state_circuit_stats {
    use crate::{
        evm_circuit::step::ExecutionState,
        stats::{bytecode_prefix_op_big_rws, print_circuit_stats_by_states},
    };

    /// Prints the stats of State circuit per execution state.  See
    /// `print_circuit_stats_by_states` for more details.
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release --all-features
    /// get_state_states_stats -- --nocapture --ignored`
    #[ignore]
    #[test]
    pub fn get_state_states_stats() {
        print_circuit_stats_by_states(
            |state| {
                // TODO: Enable CREATE/CREATE2 once they are supported
                !matches!(
                    state,
                    ExecutionState::ErrorInvalidOpcode | ExecutionState::SELFDESTRUCT
                )
            },
            bytecode_prefix_op_big_rws,
            |block, _, step_index| {
                let step = &block.txs[0].steps()[step_index];
                let step_next = &block.txs[0].steps()[step_index + 1];
                step_next.rwc.0 - step.rwc.0
            },
        );
    }
}
