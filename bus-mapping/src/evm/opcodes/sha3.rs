use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyDataType, CopyEvent, CopyStep, ExecStep, NumberOrHash,
    },
    operation::RW,
    Error,
};
use eth_types::{GethExecStep, Word, U256};
use ethers_core::utils::keccak256;

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Sha3;

impl Opcode for Sha3 {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let expected_sha3 = geth_steps[1].stack.last()?;

        // byte offset in the memory.
        let offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), offset)?;

        // byte size to read in the memory.
        let size = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), size)?;

        if size.gt(&U256::zero()) {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least(offset.as_usize() + size.as_usize());
        }

        let memory = state
            .call_ctx()?
            .memory
            .read_chunk(offset.as_usize().into(), size.as_usize().into());

        // keccak-256 hash of the given data in memory.
        let sha3 = keccak256(&memory);
        debug_assert_eq!(Word::from_big_endian(&sha3), expected_sha3);
        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.last_filled(),
            sha3.into(),
        )?;

        // Memory read operations
        let mut steps = Vec::with_capacity(2 * size.as_usize());
        for (i, byte) in memory.iter().enumerate() {
            // Read step
            steps.push(CopyStep {
                addr: offset.as_u64() + (i as u64),
                tag: CopyDataType::Memory,
                rw: RW::READ,
                value: *byte,
                is_code: None,
                is_pad: false,
                rwc: state.block_ctx.rwc,
                rwc_inc_left: 0,
            });
            state.memory_read(&mut exec_step, (offset.as_usize() + i).into(), *byte)?;
            // Write step
            steps.push(CopyStep {
                addr: i as u64,
                tag: CopyDataType::RlcAcc,
                rw: RW::WRITE,
                value: *byte,
                is_code: None,
                is_pad: false,
                rwc: state.block_ctx.rwc,
                rwc_inc_left: 0,
            })
        }
        for cs in steps.iter_mut() {
            cs.rwc_inc_left = state.block_ctx.rwc.0 as u64 - cs.rwc.0 as u64;
        }

        let call_id = state.call()?.call_id;
        state.push_copy(CopyEvent {
            src_addr: offset.as_u64(),
            src_addr_end: offset.as_u64() + size.as_u64(),
            src_type: CopyDataType::Memory,
            src_id: NumberOrHash::Number(call_id),
            dst_addr: 0,
            dst_type: CopyDataType::RlcAcc,
            dst_id: NumberOrHash::Number(call_id),
            log_id: None,
            length: size.as_u64(),
            steps,
        });

        Ok(vec![exec_step])
    }
}

#[cfg(any(feature = "test", test))]
pub mod sha3_tests {
    use eth_types::{bytecode, evm_types::OpcodeId, geth_types::GethData, Bytecode, Word};
    use ethers_core::utils::keccak256;
    use mock::{
        test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
        TestContext,
    };
    use rand::{random, Rng};

    use crate::{
        circuit_input_builder::{CopyDataType, CopyStep, ExecState},
        mock::BlockData,
        operation::{MemoryOp, RWCounter, StackOp, RW},
    };

    /// Generate bytecode for SHA3 opcode after having populated sufficient
    /// memory given the offset and size arguments for SHA3.
    pub fn gen_sha3_code(offset: usize, size: usize, mem_kind: MemoryKind) -> (Bytecode, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let data_len = match mem_kind {
            MemoryKind::LessThanSize => {
                offset
                    + if size.gt(&0) {
                        rng.gen_range(0..size)
                    } else {
                        0
                    }
            }
            MemoryKind::EqualToSize => offset + size,
            MemoryKind::MoreThanSize => {
                offset
                    + size
                    + if size.gt(&0) {
                        rng.gen_range(0..size)
                    } else {
                        0
                    }
            }
            MemoryKind::Empty => 0,
        };
        let data = rand_bytes(data_len);
        let mut memory = Vec::with_capacity(data_len);

        // add opcodes to populate memory in the current context.
        let mut code = Bytecode::default();
        for (i, mem_chunk) in data.chunks(32).enumerate() {
            let mem_value = if mem_chunk.len() < 32 {
                std::iter::repeat(0u8)
                    .take(32 - mem_chunk.len())
                    .chain(mem_chunk.to_vec())
                    .collect::<Vec<u8>>()
            } else {
                mem_chunk.to_vec()
            };
            memory.extend_from_slice(&mem_value);
            code.push(32, Word::from_big_endian(&mem_value));
            code.push(32, (32 * i).into());
            code.write_op(OpcodeId::MSTORE);
        }
        // append SHA3 related opcodes at the tail end.
        let code_tail = bytecode! {
            PUSH32(size)
            PUSH32(offset)
            SHA3
            STOP
        };
        code.append(&code_tail);
        (code, memory)
    }

    /// Memory of a context with respect to the input size to SHA3.
    pub enum MemoryKind {
        /// Variant defining empty memory.
        Empty,
        /// Variant defining memory length being less than size.
        LessThanSize,
        /// Variant defining memory length being equal to size.
        EqualToSize,
        /// Variant defining memory length being more than size.
        MoreThanSize,
    }

    fn rand_bytes(size: usize) -> Vec<u8> {
        (0..size).map(|_| random()).collect::<Vec<u8>>()
    }

    fn test_ok(offset: usize, size: usize, mem_kind: MemoryKind) {
        let (code, memory) = gen_sha3_code(offset, size, mem_kind);
        let memory_len = memory.len();

        // The memory that is hashed.
        let mut memory_view = memory
            .into_iter()
            .skip(offset)
            .take(size)
            .collect::<Vec<u8>>();
        memory_view.resize(size, 0);
        let expected_sha3_value = keccak256(&memory_view);

        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _txs| block,
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::SHA3))
            .unwrap();

        let call_id = builder.block.txs()[0].calls()[0].call_id;

        // stack read and write.
        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(call_id, 1022.into(), Word::from(offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(call_id, 1023.into(), Word::from(size)),
                ),
                (
                    RW::WRITE,
                    &StackOp::new(call_id, 1023.into(), expected_sha3_value.into()),
                ),
            ]
        );

        // Memory reads.
        // Initial memory_len bytes are the memory writes from MSTORE instruction, so we
        // skip them.
        assert_eq!(
            (memory_len..(memory_len + size))
                .map(|idx| &builder.block.container.memory[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            {
                let mut memory_ops = Vec::with_capacity(size);
                (0..size).for_each(|idx| {
                    let value = memory_view[idx];
                    memory_ops.push((
                        RW::READ,
                        MemoryOp::new(call_id, (offset + idx).into(), value),
                    ));
                });
                memory_ops
            },
        );

        let copy_events = builder.block.copy_events.clone();

        // single copy event with `size` reads and `size` writes.
        assert_eq!(copy_events.len(), 1);
        assert_eq!(copy_events[0].steps.len(), 2 * size);

        let mut rwc = RWCounter(step.rwc.0 + 3); // 2 stack reads and 1 stack write.
        for (idx, copy_rw_pair) in copy_events[0].steps.chunks(2).enumerate() {
            assert_eq!(copy_rw_pair.len(), 2);
            let value = memory_view[idx];
            // read
            let read_step = copy_rw_pair[0].clone();
            assert_eq!(
                read_step,
                CopyStep {
                    addr: (offset + idx) as u64,
                    tag: CopyDataType::Memory,
                    rw: RW::READ,
                    value,
                    is_code: None,
                    is_pad: false,
                    rwc: rwc.inc_pre(),
                    rwc_inc_left: (size - idx) as u64,
                }
            );
            // write
            let write_step = copy_rw_pair[1].clone();
            assert_eq!(
                write_step,
                CopyStep {
                    addr: idx as u64,
                    tag: CopyDataType::RlcAcc,
                    rw: RW::WRITE,
                    value,
                    is_code: None,
                    is_pad: false,
                    rwc,
                    rwc_inc_left: (size - idx - 1) as u64,
                }
            );
        }
    }

    #[test]
    fn sha3_opcode_ok() {
        test_ok(0x10, 0x32, MemoryKind::Empty);
        test_ok(0x34, 0x44, MemoryKind::LessThanSize);
        test_ok(0x222, 0x111, MemoryKind::EqualToSize);
        test_ok(0x20, 0x30, MemoryKind::MoreThanSize);
    }
}
