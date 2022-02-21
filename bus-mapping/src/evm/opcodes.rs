//! Definition of each opcode of the EVM.
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;
use core::fmt::Debug;
use eth_types::GethExecStep;

mod caller;
mod callvalue;
mod coinbase;
mod dup;
mod gas;
mod jump;
mod jumpdest;
mod jumpi;
mod mload;
mod msize;
mod mstore;
mod pc;
mod pop;
mod push;
mod sload;
mod stackonlyop;
mod stop;
mod swap;
mod timestamp;
use crate::evm::OpcodeId;
use log::warn;

use self::push::Push;
use caller::Caller;
use callvalue::Callvalue;
use dup::Dup;
use gas::Gas;
use jump::Jump;
use jumpdest::Jumpdest;
use jumpi::Jumpi;
use mload::Mload;
use msize::Msize;
use mstore::Mstore;
use pc::Pc;
use pop::Pop;
use sload::Sload;
use stackonlyop::StackOnlyOpcode;
use stop::Stop;
use swap::Swap;

/// Generic opcode trait which defines the logic of the
/// [`Operation`](crate::operation::Operation) that should be generated for one
/// or multiple [`ExecStep`](crate::circuit_input_builder::ExecStep) depending
/// of the [`OpcodeId`] it contains.
pub trait Opcode: Debug {
    /// Generate the associated [`MemoryOp`](crate::operation::MemoryOp)s,
    /// [`StackOp`](crate::operation::StackOp)s, and
    /// [`StorageOp`](crate::operation::StorageOp)s associated to the Opcode
    /// is implemented for.
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        exec_step: &mut ExecStep,
        next_steps: &[GethExecStep],
    ) -> Result<(), Error>;

    ///
    fn gen_associated_ops_multi(
        state: &mut CircuitInputStateRef,
        next_steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let mut step = state.new_step(&next_steps[0]);
        Self::gen_associated_ops(state, &mut step, next_steps)?;
        state.push_step_to_tx(step);
        Ok(())
    }
}

fn dummy_gen_associated_ops(
    _state: &mut CircuitInputStateRef,
    _next_steps: &[GethExecStep],
) -> Result<(), Error> {
    Ok(())
}

type FnGenAssociatedOps =
    fn(state: &mut CircuitInputStateRef, next_steps: &[GethExecStep]) -> Result<(), Error>;

fn fn_gen_associated_ops(opcode_id: &OpcodeId) -> FnGenAssociatedOps {
    match opcode_id {
        OpcodeId::STOP => Stop::gen_associated_ops_multi,
        OpcodeId::ADD => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::MUL => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SUB => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::DIV => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SDIV => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::MOD => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SMOD => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::ADDMOD => StackOnlyOpcode::<3>::gen_associated_ops_multi,
        OpcodeId::MULMOD => StackOnlyOpcode::<3>::gen_associated_ops_multi,
        OpcodeId::EXP => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SIGNEXTEND => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::LT => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::GT => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SLT => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SGT => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::EQ => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::ISZERO => StackOnlyOpcode::<1>::gen_associated_ops_multi,
        OpcodeId::AND => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::OR => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::XOR => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::NOT => StackOnlyOpcode::<1>::gen_associated_ops_multi,
        OpcodeId::BYTE => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SHL => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SHR => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        OpcodeId::SAR => StackOnlyOpcode::<2>::gen_associated_ops_multi,
        // OpcodeId::SHA3 => {},
        // OpcodeId::ADDRESS => {},
        // OpcodeId::BALANCE => {},
        // OpcodeId::ORIGIN => {},
        OpcodeId::CALLER => Caller::gen_associated_ops_multi,
        OpcodeId::CALLVALUE => Callvalue::gen_associated_ops_multi,
        // OpcodeId::CALLDATALOAD => {},
        // OpcodeId::CALLDATASIZE => {},
        // OpcodeId::CALLDATACOPY => {},
        // OpcodeId::CODESIZE => {},
        // OpcodeId::CODECOPY => {},
        // OpcodeId::GASPRICE => {},
        // OpcodeId::EXTCODESIZE => {},
        // OpcodeId::EXTCODECOPY => {},
        // OpcodeId::RETURNDATASIZE => {},
        // OpcodeId::RETURNDATACOPY => {},
        // OpcodeId::EXTCODEHASH => {},
        // OpcodeId::BLOCKHASH => {},
        OpcodeId::COINBASE => StackOnlyOpcode::<0>::gen_associated_ops_multi,
        OpcodeId::TIMESTAMP => StackOnlyOpcode::<0>::gen_associated_ops_multi,
        // OpcodeId::NUMBER => {},
        // OpcodeId::DIFFICULTY => {},
        // OpcodeId::GASLIMIT => {},
        // OpcodeId::CHAINID => {},
        // OpcodeId::SELFBALANCE => {},
        // OpcodeId::BASEFEE => {},
        OpcodeId::POP => Pop::gen_associated_ops_multi,
        OpcodeId::MLOAD => Mload::gen_associated_ops_multi,
        OpcodeId::MSTORE => Mstore::<false>::gen_associated_ops_multi,
        OpcodeId::MSTORE8 => Mstore::<true>::gen_associated_ops_multi,
        OpcodeId::SLOAD => Sload::gen_associated_ops_multi,
        // OpcodeId::SSTORE => {},
        OpcodeId::JUMP => Jump::gen_associated_ops_multi,
        OpcodeId::JUMPI => Jumpi::gen_associated_ops_multi,
        OpcodeId::PC => Pc::gen_associated_ops_multi,
        OpcodeId::MSIZE => Msize::gen_associated_ops_multi,
        OpcodeId::GAS => Gas::gen_associated_ops_multi,
        OpcodeId::JUMPDEST => Jumpdest::gen_associated_ops_multi,
        OpcodeId::PUSH1 => Push::<1>::gen_associated_ops_multi,
        OpcodeId::PUSH2 => Push::<2>::gen_associated_ops_multi,
        OpcodeId::PUSH3 => Push::<3>::gen_associated_ops_multi,
        OpcodeId::PUSH4 => Push::<4>::gen_associated_ops_multi,
        OpcodeId::PUSH5 => Push::<5>::gen_associated_ops_multi,
        OpcodeId::PUSH6 => Push::<6>::gen_associated_ops_multi,
        OpcodeId::PUSH7 => Push::<7>::gen_associated_ops_multi,
        OpcodeId::PUSH8 => Push::<8>::gen_associated_ops_multi,
        OpcodeId::PUSH9 => Push::<9>::gen_associated_ops_multi,
        OpcodeId::PUSH10 => Push::<10>::gen_associated_ops_multi,
        OpcodeId::PUSH11 => Push::<11>::gen_associated_ops_multi,
        OpcodeId::PUSH12 => Push::<12>::gen_associated_ops_multi,
        OpcodeId::PUSH13 => Push::<13>::gen_associated_ops_multi,
        OpcodeId::PUSH14 => Push::<14>::gen_associated_ops_multi,
        OpcodeId::PUSH15 => Push::<15>::gen_associated_ops_multi,
        OpcodeId::PUSH16 => Push::<16>::gen_associated_ops_multi,
        OpcodeId::PUSH17 => Push::<17>::gen_associated_ops_multi,
        OpcodeId::PUSH18 => Push::<18>::gen_associated_ops_multi,
        OpcodeId::PUSH19 => Push::<19>::gen_associated_ops_multi,
        OpcodeId::PUSH20 => Push::<20>::gen_associated_ops_multi,
        OpcodeId::PUSH21 => Push::<21>::gen_associated_ops_multi,
        OpcodeId::PUSH22 => Push::<22>::gen_associated_ops_multi,
        OpcodeId::PUSH23 => Push::<23>::gen_associated_ops_multi,
        OpcodeId::PUSH24 => Push::<24>::gen_associated_ops_multi,
        OpcodeId::PUSH25 => Push::<25>::gen_associated_ops_multi,
        OpcodeId::PUSH26 => Push::<26>::gen_associated_ops_multi,
        OpcodeId::PUSH27 => Push::<27>::gen_associated_ops_multi,
        OpcodeId::PUSH28 => Push::<28>::gen_associated_ops_multi,
        OpcodeId::PUSH29 => Push::<29>::gen_associated_ops_multi,
        OpcodeId::PUSH30 => Push::<30>::gen_associated_ops_multi,
        OpcodeId::PUSH31 => Push::<31>::gen_associated_ops_multi,
        OpcodeId::PUSH32 => Push::<32>::gen_associated_ops_multi,
        OpcodeId::DUP1 => Dup::<1>::gen_associated_ops_multi,
        OpcodeId::DUP2 => Dup::<2>::gen_associated_ops_multi,
        OpcodeId::DUP3 => Dup::<3>::gen_associated_ops_multi,
        OpcodeId::DUP4 => Dup::<4>::gen_associated_ops_multi,
        OpcodeId::DUP5 => Dup::<5>::gen_associated_ops_multi,
        OpcodeId::DUP6 => Dup::<6>::gen_associated_ops_multi,
        OpcodeId::DUP7 => Dup::<7>::gen_associated_ops_multi,
        OpcodeId::DUP8 => Dup::<8>::gen_associated_ops_multi,
        OpcodeId::DUP9 => Dup::<9>::gen_associated_ops_multi,
        OpcodeId::DUP10 => Dup::<10>::gen_associated_ops_multi,
        OpcodeId::DUP11 => Dup::<11>::gen_associated_ops_multi,
        OpcodeId::DUP12 => Dup::<12>::gen_associated_ops_multi,
        OpcodeId::DUP13 => Dup::<13>::gen_associated_ops_multi,
        OpcodeId::DUP14 => Dup::<14>::gen_associated_ops_multi,
        OpcodeId::DUP15 => Dup::<15>::gen_associated_ops_multi,
        OpcodeId::DUP16 => Dup::<16>::gen_associated_ops_multi,
        OpcodeId::SWAP1 => Swap::<1>::gen_associated_ops_multi,
        OpcodeId::SWAP2 => Swap::<2>::gen_associated_ops_multi,
        OpcodeId::SWAP3 => Swap::<3>::gen_associated_ops_multi,
        OpcodeId::SWAP4 => Swap::<4>::gen_associated_ops_multi,
        OpcodeId::SWAP5 => Swap::<5>::gen_associated_ops_multi,
        OpcodeId::SWAP6 => Swap::<6>::gen_associated_ops_multi,
        OpcodeId::SWAP7 => Swap::<7>::gen_associated_ops_multi,
        OpcodeId::SWAP8 => Swap::<8>::gen_associated_ops_multi,
        OpcodeId::SWAP9 => Swap::<9>::gen_associated_ops_multi,
        OpcodeId::SWAP10 => Swap::<10>::gen_associated_ops_multi,
        OpcodeId::SWAP11 => Swap::<11>::gen_associated_ops_multi,
        OpcodeId::SWAP12 => Swap::<12>::gen_associated_ops_multi,
        OpcodeId::SWAP13 => Swap::<13>::gen_associated_ops_multi,
        OpcodeId::SWAP14 => Swap::<14>::gen_associated_ops_multi,
        OpcodeId::SWAP15 => Swap::<15>::gen_associated_ops_multi,
        OpcodeId::SWAP16 => Swap::<16>::gen_associated_ops_multi,
        // OpcodeId::LOG0 => {},
        // OpcodeId::LOG1 => {},
        // OpcodeId::LOG2 => {},
        // OpcodeId::LOG3 => {},
        // OpcodeId::LOG4 => {},
        // OpcodeId::CREATE => {},
        // OpcodeId::CALL => {},
        // OpcodeId::CALLCODE => {},
        // OpcodeId::RETURN => {},
        // OpcodeId::DELEGATECALL => {},
        // OpcodeId::CREATE2 => {},
        // OpcodeId::STATICCALL => {},
        // OpcodeId::REVERT => {},
        // OpcodeId::SELFDESTRUCT => {},
        // _ => panic!("Opcode {:?} gen_associated_ops not implemented",
        // self),
        _ => {
            warn!("Using dummy gen_associated_ops for opcode {:?}", opcode_id);
            dummy_gen_associated_ops
        }
    }
}

/// Generate the associated operations according to the particular
/// [`OpcodeId`].
pub fn gen_associated_ops(
    opcode_id: &OpcodeId,
    state: &mut CircuitInputStateRef,
    next_steps: &[GethExecStep],
) -> Result<(), Error> {
    let fn_gen_associated_ops = fn_gen_associated_ops(opcode_id);
    fn_gen_associated_ops(state, next_steps)
}
