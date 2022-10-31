//! Mutations
use bus_mapping::{circuit_input_builder, evm::OpcodeId};
use bus_mapping::circuit_input_builder::CircuitInputBuilder;
use bus_mapping::circuit_input_builder::ExecState;

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

/// Dummy mutation to the traces of MUL opcode
pub fn mutate(builder: CircuitInputBuilder) -> CircuitInputBuilder {
    //builder.block.txs[0].steps()[0].
    println!("{:#?}", builder);
    for step in builder.block.txs[0].steps() {
        match step.exec_state {
            ExecState::Op(op) => {
                match op {
                    OpcodeId::MUL => {
                        // Contains three references
                        //println!("{:?}", step.bus_mapping_instance[2]);
                    }
                    _ => {} 
                }
            }
            _ => {}
        }
    }
    return builder;
}
