use crate::{evm_circuit::step::ExecutionResult, impl_expr};
use halo2::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use std::iter;

pub(crate) trait LookupTable<F: FieldExt, const W: usize> {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> [Expression<F>; W];
}

impl<F: FieldExt, const W: usize> LookupTable<F, W> for [Column<Advice>; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> [Expression<F>; W] {
        self.map(|column| meta.query_advice(column, Rotation::cur()))
    }
}

impl<F: FieldExt, const W: usize> LookupTable<F, W> for [Column<Fixed>; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> [Expression<F>; W] {
        self.map(|column| meta.query_fixed(column, Rotation::cur()))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FixedTableTag {
    Range16 = 1,
    Range17,
    Range32,
    Range256,
    Range512,
    SignByte,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    ResponsibleOpcode,
}

impl FixedTableTag {
    pub(crate) fn build_all<F: FieldExt>() -> impl Iterator<Item = Vec<F>> {
        iter::once(vec![F::zero(), F::zero(), F::zero(), F::zero()])
            .chain(Self::Range16.build())
            .chain(Self::Range17.build())
            .chain(Self::Range32.build())
            .chain(Self::Range256.build())
            .chain(Self::Range512.build())
            .chain(Self::SignByte.build())
            // Enable bitwise when testing time too long issue is resolved, see
            // https://github.com/appliedzkp/zkevm-circuits/issues/88 for more information.
            // .chain(Self::BitwiseAnd.build())
            // .chain(Self::BitwiseOr.build())
            // .chain(Self::BitwiseXor.build())
            .chain(Self::ResponsibleOpcode.build())
    }

    fn build<F: FieldExt>(&self) -> Box<dyn Iterator<Item = Vec<F>>> {
        let tag = F::from(*self as u64);
        match self {
            Self::Range16 => Box::new((0..16).map(move |value| {
                vec![tag, F::from(value), F::zero(), F::zero()]
            })),
            Self::Range17 => Box::new((0..17).map(move |value| {
                vec![tag, F::from(value), F::zero(), F::zero()]
            })),
            Self::Range32 => Box::new((0..32).map(move |value| {
                vec![tag, F::from(value), F::zero(), F::zero()]
            })),
            Self::Range256 => Box::new((0..256).map(move |value| {
                vec![tag, F::from(value), F::zero(), F::zero()]
            })),
            Self::Range512 => Box::new((0..512).map(move |value| {
                vec![tag, F::from(value), F::zero(), F::zero()]
            })),
            Self::SignByte => Box::new((0..256).map(move |value| {
                vec![
                    tag,
                    F::from(value),
                    F::from((value >> 7) * 0xFFu64),
                    F::zero(),
                ]
            })),
            Self::BitwiseAnd => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| {
                    vec![tag, F::from(lhs), F::from(rhs), F::from(lhs & rhs)]
                })
            })),
            Self::BitwiseOr => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| {
                    vec![tag, F::from(lhs), F::from(rhs), F::from(lhs | rhs)]
                })
            })),
            Self::BitwiseXor => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| {
                    vec![tag, F::from(lhs), F::from(rhs), F::from(lhs ^ rhs)]
                })
            })),
            Self::ResponsibleOpcode => Box::new(
                ExecutionResult::iterator().flat_map(move |execution_result| {
                    execution_result.responsible_opcodes().into_iter().map(
                        move |opcode| {
                            vec![
                                tag,
                                F::from_u64(execution_result.as_u64()),
                                F::from_u64(opcode.as_u64()),
                                F::zero(),
                            ]
                        },
                    )
                }),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum TxTableTag {
    Nonce = 1,
    Gas,
    GasTipCap,
    GasFeeCap,
    CallerAddress,
    CalleeAddress,
    IsCreate,
    Value,
    CalldataLength,
    Calldata,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RwTableTag {
    TxAccessListAccount = 1,
    TxAccessListStorageSlot,
    TxRefund,
    Account,
    AccountStorage,
    AccountDestructed,
    CallContext,
    Stack,
    Memory,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AccountFieldTag {
    Nonce = 1,
    Balance,
    CodeHash,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CallContextFieldTag {
    RWCounterEndOfReversion = 1,
    CallerCallId,
    TxId,
    Depth,
    CallerAddress,
    CalleeAddress,
    CalldataOffset,
    CalldataLength,
    ReturndataOffset,
    ReturndataLength,
    Value,
    Result,
    IsPersistent,
    IsStatic,

    IsRoot,
    IsCreate,
    OpcodeSource,
    ProgramCounter,
    StackPointer,
    GasLeft,
    MemorySize,
    StateWriteCounter,
}

impl_expr!(FixedTableTag);
impl_expr!(TxTableTag);
impl_expr!(RwTableTag);
impl_expr!(AccountFieldTag);
impl_expr!(CallContextFieldTag);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Table {
    Fixed,
    Tx,
    Rw,
    Bytecode,
}

#[derive(Clone, Debug)]
pub(crate) enum Lookup<F> {
    Fixed {
        tag: Expression<F>,
        values: [Expression<F>; 3],
    },
    Tx {
        id: Expression<F>,
        tag: Expression<F>,
        index: Expression<F>,
        value: Expression<F>,
    },
    Rw {
        counter: Expression<F>,
        is_write: Expression<F>,
        tag: Expression<F>,
        values: [Expression<F>; 5],
    },
    Bytecode {
        hash: Expression<F>,
        index: Expression<F>,
        value: Expression<F>,
    },
    Conditional(Expression<F>, Box<Lookup<F>>),
}

impl<F: FieldExt> Lookup<F> {
    pub(crate) fn conditional(self, condition: Expression<F>) -> Self {
        Self::Conditional(condition, self.into())
    }

    pub(crate) fn table(&self) -> Table {
        match self {
            Self::Fixed { .. } => Table::Fixed,
            Self::Tx { .. } => Table::Tx,
            Self::Rw { .. } => Table::Rw,
            Self::Bytecode { .. } => Table::Bytecode,
            Self::Conditional(_, lookup) => lookup.table(),
        }
    }

    pub(crate) fn input_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Self::Fixed { tag, values } => {
                [vec![tag.clone()], values.to_vec()].concat()
            }
            Self::Tx {
                id,
                tag,
                index,
                value,
            } => vec![id.clone(), tag.clone(), index.clone(), value.clone()],
            Self::Rw {
                counter,
                is_write,
                tag,
                values,
            } => [
                vec![counter.clone(), is_write.clone(), tag.clone()],
                values.to_vec(),
            ]
            .concat(),
            Self::Bytecode { hash, index, value } => {
                vec![hash.clone(), index.clone(), value.clone()]
            }
            Self::Conditional(condition, lookup) => lookup
                .input_exprs()
                .into_iter()
                .map(|expr| condition.clone() * expr)
                .collect(),
        }
    }

    pub(crate) fn degree(&self) -> usize {
        self.input_exprs()
            .iter()
            .map(|expr| expr.degree())
            .max()
            .unwrap()
    }
}
