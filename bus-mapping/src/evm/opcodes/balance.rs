use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::opcodes::stackonlyop::StackOnlyOpcode;
use crate::evm::Opcode;
use crate::Error;
use eth_types::{Address, GethExecStep, ToAddress};

#[derive(Debug, Copy, Clone)]
pub(crate) struct Balance;

impl Opcode for Balance {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        StackOnlyOpcode::<1, 1>.gen_associated_ops(state, geth_steps)
    }

    fn reconstruct_accessed_addresses(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Option<Vec<Address>>, Error> {
        let address = geth_steps[0].stack.nth_last(0)?.to_address();
        if state.sdb.add_account_to_access_list(address) {
            Ok(Some(vec![address]))
        } else {
            Ok(None)
        }
    }
}
