use super::{step::step_convert, Call, ExecStep};
use crate::{
    evm_circuit::{step::ExecutionState, util::rlc},
    table::TxContextFieldTag,
    util::{rlc_be_bytes, Challenges},
};
use bus_mapping::{
    circuit_input_builder,
    circuit_input_builder::{get_dummy_tx, get_dummy_tx_hash},
};
#[cfg(feature = "kroma")]
use eth_types::geth_types::{Transaction as GethTransaction, DEPOSIT_TX_TYPE};
use eth_types::{
    evm_types::rwc_util::end_tx_rwc,
    sign_types::{biguint_to_32bytes_le, ct_option_ok_or, recover_pk, SignData, SECP256K1_Q},
    Address, Error, Field, Hash, Signature, ToBigEndian, ToLittleEndian, ToScalar, ToWord, Word,
    H256,
};
use ethers_core::utils::{
    keccak256,
    rlp::{Encodable, RlpStream},
};
use halo2_proofs::{
    circuit::Value,
    halo2curves::{group::ff::PrimeField, secp256k1},
};
use mock::MockTransaction;
use num::Integer;
use num_bigint::BigUint;

/// Transaction in a witness block
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The block number in which this tx is included in
    pub block_number: u64,
    /// The transaction identifier in the block
    pub id: usize,
    /// The hash of the transaction
    pub hash: H256,
    /// The type of the transaction
    pub transaction_type: u64,
    /// The sender account nonce of the transaction
    pub nonce: u64,
    /// The gas limit of the transaction
    pub gas: u64,
    /// The gas price
    pub gas_price: Word,
    /// The caller address
    pub caller_address: Address,
    /// The callee address
    pub callee_address: Option<Address>,
    /// Whether it's a create transaction
    pub is_create: bool,
    /// The ether amount of the transaction
    pub value: Word,
    /// The call data
    pub call_data: Vec<u8>,
    /// The call data length
    pub call_data_length: usize,
    /// The gas cost for transaction call data
    pub call_data_gas_cost: u64,
    /// Chain ID as per EIP-155.
    pub chain_id: u64,
    /// Rlp-encoded bytes of unsigned tx
    pub rlp_unsigned: Vec<u8>,
    /// Rlp-encoded bytes of unsigned tx
    pub rlp_signed: Vec<u8>,
    /// "v" value of the transaction signature
    pub v: u64,
    /// "r" value of the transaction signature
    pub r: Word,
    /// "s" value of the transaction signature
    pub s: Word,
    /// The calls made in the transaction
    pub calls: Vec<Call>,
    /// The steps executioned in the transaction
    pub steps: Vec<ExecStep>,

    /// Kroma deposit tx
    #[cfg(feature = "kroma")]
    /// The mint
    pub mint: Word,
    #[cfg(feature = "kroma")]
    /// The source hash
    pub source_hash: Hash,

    /// Kroma non-deposit tx
    #[cfg(feature = "kroma")]
    /// The gas cost that needs to be rolled up to L1.
    pub rollup_data_gas_cost: u64,
}

impl Transaction {
    /// Whether tx is a system deposit tx.
    pub fn is_system_deposit(&self) -> bool {
        self.is_deposit() && self.id == 1
    }

    /// Whether tx is a deposit tx.
    pub fn is_deposit(&self) -> bool {
        #[cfg(feature = "kroma")]
        return self.transaction_type == DEPOSIT_TX_TYPE;
        #[cfg(not(feature = "kroma"))]
        return false;
    }

    /// Assignments for tx table, split into tx_data (all fields except
    /// calldata) and tx_calldata
    /// Return a fixed dummy tx for chain_id
    pub fn dummy(chain_id: u64) -> Self {
        let (dummy_tx, dummy_sig) = get_dummy_tx(chain_id);
        let dummy_tx_hash = get_dummy_tx_hash(chain_id);
        let rlp_signed = dummy_tx.rlp_signed(&dummy_sig).to_vec();
        let rlp_unsigned = dummy_tx.rlp().to_vec();

        Self {
            block_number: 0, // FIXME
            id: 0,           // need to be changed to correct value
            caller_address: Address::zero(),
            callee_address: Some(Address::zero()),
            is_create: false, // callee_address != None
            chain_id,
            v: dummy_sig.v,
            r: dummy_sig.r,
            s: dummy_sig.s,
            rlp_signed,
            rlp_unsigned,
            hash: dummy_tx_hash,

            ..Default::default()
        }
    }
    /// Sign data
    pub fn sign_data(&self) -> Result<SignData, Error> {
        let sig_r_le = self.r.to_le_bytes();
        let sig_s_le = self.s.to_le_bytes();
        #[cfg(not(feature = "kroma"))]
        let zero_signature = false;
        #[cfg(feature = "kroma")]
        let zero_signature = self.is_deposit();
        let sig_r = if zero_signature {
            secp256k1::Fq::zero()
        } else {
            ct_option_ok_or(
                secp256k1::Fq::from_repr(sig_r_le),
                Error::Signature(libsecp256k1::Error::InvalidSignature),
            )?
        };
        let sig_s = if zero_signature {
            secp256k1::Fq::zero()
        } else {
            ct_option_ok_or(
                secp256k1::Fq::from_repr(sig_s_le),
                Error::Signature(libsecp256k1::Error::InvalidSignature),
            )?
        };
        let msg = self.rlp_unsigned.clone().into();
        let msg_hash = keccak256(&self.rlp_unsigned);
        let v = ((self.v + 1) % 2) as u8;
        let pk = if zero_signature {
            halo2_proofs::halo2curves::secp256k1::Secp256k1Affine::generator()
        } else {
            recover_pk(v, &self.r, &self.s, &msg_hash)?
        };
        // msg_hash = msg_hash % q
        let msg_hash = BigUint::from_bytes_be(msg_hash.as_slice());
        let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
        let msg_hash_le = biguint_to_32bytes_le(msg_hash);
        let msg_hash = ct_option_ok_or(
            secp256k1::Fq::from_repr(msg_hash_le),
            libsecp256k1::Error::InvalidMessage,
        )?;
        Ok(SignData {
            signature: (sig_r, sig_s),
            pk,
            msg,
            msg_hash,
        })
    }

    /// Assignments for tx table
    pub fn table_assignments_fixed<F: Field>(
        &self,
        challenges: Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        let rlp_signed_hash = H256(keccak256(&self.rlp_signed));
        if self.hash != rlp_signed_hash {
            log::debug!(
                "assign a non-legacy tx (hash = {}, rlp_signed_hash = {}) in tx table",
                self.hash,
                rlp_signed_hash
            );
        }
        let tx_hash_be_bytes = rlp_signed_hash.to_fixed_bytes();
        let tx_sign_hash_be_bytes = keccak256(&self.rlp_unsigned);
        let source_hash_be_bytes = self.source_hash.to_fixed_bytes();

        let ret = vec![
            #[cfg(feature = "kroma")]
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::Type as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.transaction_type)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::Nonce as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.nonce)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::GasPrice as u64)),
                Value::known(F::zero()),
                challenges
                    .evm_word()
                    .map(|challenge| rlc::value(&self.gas_price.to_le_bytes(), challenge)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::Gas as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.gas)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::CallerAddress as u64)),
                Value::known(F::zero()),
                Value::known(self.caller_address.to_scalar().unwrap()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::CalleeAddress as u64)),
                Value::known(F::zero()),
                Value::known(
                    self.callee_address
                        .unwrap_or(Address::zero())
                        .to_scalar()
                        .unwrap(),
                ),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::IsCreate as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.is_create as u64)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::Value as u64)),
                Value::known(F::zero()),
                challenges
                    .evm_word()
                    .map(|challenge| rlc::value(&self.value.to_le_bytes(), challenge)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::CallDataLength as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.call_data_length as u64)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::CallDataGasCost as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.call_data_gas_cost)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::SigV as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.v)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::SigR as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.r.to_be_bytes(), challenges.evm_word()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::SigS as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.s.to_be_bytes(), challenges.evm_word()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxSignLength as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.rlp_unsigned.len() as u64)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxSignRLC as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.rlp_unsigned, challenges.keccak_input()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxSignHash as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&tx_sign_hash_be_bytes, challenges.evm_word()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxHashLength as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.rlp_signed.len() as u64)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxHashRLC as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.rlp_signed, challenges.keccak_input()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxHash as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&tx_hash_be_bytes, challenges.evm_word()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::BlockNumber as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.block_number)),
            ],
            #[cfg(feature = "kroma")]
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::Mint as u64)),
                Value::known(F::zero()),
                challenges
                    .evm_word()
                    .map(|challenge| rlc::value(&self.mint.to_le_bytes(), challenge)),
            ],
            #[cfg(feature = "kroma")]
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::SourceHash as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&source_hash_be_bytes, challenges.evm_word()),
            ],
            #[cfg(feature = "kroma")]
            // NOTE(chokobole): The reason why rlc encoding rollup_data_gas_cost is
            // because it is used to add with another rlc value in RollupFeeHook gadget.
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::RollupDataGasCost as u64)),
                Value::known(F::zero()),
                challenges.evm_word().map(|challenge| {
                    rlc::value(&self.rollup_data_gas_cost.to_le_bytes(), challenge)
                }),
            ],
        ];

        ret
    }

    /// Assignments for tx table
    pub fn table_assignments_dyn<F: Field>(
        &self,
        _challenges: Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        self.call_data
            .iter()
            .enumerate()
            .map(|(idx, byte)| {
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::CallData as u64)),
                    Value::known(F::from(idx as u64)),
                    Value::known(F::from(*byte as u64)),
                ]
            })
            .collect()
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self.transaction_type {
            0 => {
                s.begin_list(9);
                s.append(&Word::from(self.nonce));
                s.append(&self.gas_price);
                s.append(&Word::from(self.gas));
                if let Some(addr) = self.callee_address {
                    s.append(&addr);
                } else {
                    s.append(&"");
                }
                s.append(&self.value);
                s.append(&self.call_data);
                s.append(&Word::from(self.chain_id));
                s.append(&Word::zero());
                s.append(&Word::zero());
            }
            #[cfg(feature = "kroma")]
            DEPOSIT_TX_TYPE => {
                s.append(&self.transaction_type);
                s.begin_list(7);
                s.append(&Word::from(self.source_hash.to_fixed_bytes()));
                s.append(&self.caller_address);
                if let Some(addr) = self.callee_address {
                    s.append(&addr);
                } else {
                    s.append(&"");
                }
                s.append(&self.mint);
                s.append(&self.value);
                s.append(&self.gas);
                s.append(&self.call_data);
            }
            _ => panic!("not supported transaction type"),
        }
    }
}

/// Signed transaction in a witness block
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// Transaction data.
    pub tx: Transaction,
    /// ECDSA signature on the transaction.
    pub signature: Signature,
}

impl Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self.tx.transaction_type {
            0 => {
                s.begin_list(9);
                s.append(&Word::from(self.tx.nonce));
                s.append(&self.tx.gas_price);
                s.append(&Word::from(self.tx.gas));
                if let Some(addr) = self.tx.callee_address {
                    s.append(&addr);
                } else {
                    s.append(&"");
                }
                s.append(&self.tx.value);
                s.append(&self.tx.call_data);
                s.append(&self.signature.v);
                s.append(&self.signature.r);
                s.append(&self.signature.s);
            }
            #[cfg(feature = "kroma")]
            DEPOSIT_TX_TYPE => {
                s.append(&self.tx.transaction_type);
                s.begin_list(7);
                s.append(&Word::from(self.tx.source_hash.to_fixed_bytes()));
                s.append(&self.tx.caller_address);
                if let Some(addr) = self.tx.callee_address {
                    s.append(&addr);
                } else {
                    s.append(&"");
                }
                s.append(&self.tx.mint);
                s.append(&self.tx.value);
                s.append(&self.tx.gas);
                s.append(&self.tx.call_data);
            }
            _ => panic!("not supported transaction type"),
        }
    }
}

impl From<MockTransaction> for Transaction {
    fn from(mock_tx: MockTransaction) -> Self {
        let is_create = mock_tx.to.is_none();
        let sig = Signature {
            r: mock_tx.r.expect("tx expected to be signed"),
            s: mock_tx.s.expect("tx expected to be signed"),
            v: mock_tx.v.expect("tx expected to be signed").as_u64(),
        };
        let rlp_unsigned = GethTransaction::from(&mock_tx)
            .rlp_unsigned(mock_tx.chain_id.as_u64())
            .to_vec();
        let rlp_signed = GethTransaction::from(&mock_tx).rlp_signed().to_vec();

        Self {
            block_number: 1,
            id: mock_tx.transaction_index.as_usize(),
            hash: mock_tx.hash.unwrap_or_default(),
            nonce: mock_tx.nonce,
            gas: mock_tx.gas.as_u64(),
            gas_price: mock_tx.gas_price,
            caller_address: mock_tx.from.address(),
            callee_address: mock_tx.to.as_ref().map(|to| to.address()),
            is_create,
            value: mock_tx.value,
            call_data: mock_tx.input.to_vec(),
            call_data_length: mock_tx.input.len(),
            call_data_gas_cost: mock_tx
                .input
                .iter()
                .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
            chain_id: mock_tx.chain_id.as_u64(),
            rlp_unsigned,
            rlp_signed,
            v: sig.v,
            r: sig.r,
            s: sig.s,
            calls: vec![],
            steps: vec![],
            transaction_type: mock_tx.transaction_type.as_u64(),
            #[cfg(feature = "kroma")]
            mint: mock_tx.mint,
            #[cfg(feature = "kroma")]
            source_hash: mock_tx.source_hash,
            #[cfg(feature = "kroma")]
            rollup_data_gas_cost: 1000,
        }
    }
}
impl From<MockTransaction> for SignedTransaction {
    fn from(mock_tx: MockTransaction) -> Self {
        SignedTransaction::from(&Transaction::from(mock_tx))
    }
}

pub(super) fn tx_convert(
    tx: &circuit_input_builder::Transaction,
    id: usize,
    chain_id: u64,
    next_block_num: u64,
) -> Transaction {
    // NOTE(chokobole): tx.chain_id is 0 when retrieving transactions from getBlockByNumber()
    // during integration test.
    // debug_assert_eq!(
    //     chain_id, tx.chain_id,
    //     "block.chain_id = {}, tx.chain_id = {}",
    //     chain_id, tx.chain_id
    // );

    let rlp_unsigned = GethTransaction::from(tx).rlp_unsigned(chain_id).to_vec();
    let rlp_signed = GethTransaction::from(tx).rlp_signed().to_vec();

    Transaction {
        block_number: tx.block_num,
        id,
        hash: tx.hash, // NOTE that if tx is not of legacy type, then tx.hash does not equal to
        // keccak(rlp_signed)
        transaction_type: tx.transaction_type,
        nonce: tx.nonce,
        gas: tx.gas,
        gas_price: tx.gas_price,
        caller_address: tx.from,
        callee_address: tx.to,
        is_create: tx.is_create(),
        value: tx.value,
        call_data: tx.input.clone(),
        call_data_length: tx.input.len(),
        #[cfg(feature = "kroma")]
        mint: tx.mint,
        #[cfg(feature = "kroma")]
        source_hash: tx.source_hash,
        #[cfg(feature = "kroma")]
        rollup_data_gas_cost: tx.rollup_data_gas_cost,
        call_data_gas_cost: tx
            .input
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
        chain_id,
        rlp_unsigned,
        rlp_signed,
        v: tx.signature.v,
        r: tx.signature.r,
        s: tx.signature.s,
        calls: tx
            .calls()
            .iter()
            .map(|call| Call {
                id: call.call_id,
                is_root: call.is_root,
                is_create: call.is_create(),
                code_hash: call.code_hash.to_word(),
                rw_counter_end_of_reversion: call.rw_counter_end_of_reversion,
                caller_id: call.caller_id,
                depth: call.depth,
                caller_address: call.caller_address,
                callee_address: call.address,
                call_data_offset: call.call_data_offset,
                call_data_length: call.call_data_length,
                return_data_offset: call.return_data_offset,
                return_data_length: call.return_data_length,
                value: call.value,
                is_success: call.is_success,
                is_persistent: call.is_persistent,
                is_static: call.is_static,
            })
            .collect(),
        steps: tx
            .steps()
            .iter()
            .map(|step| step_convert(step, tx.block_num))
            .chain({
                let rwc =
                    tx.steps().last().unwrap().rwc.0 + end_tx_rwc(tx.transaction_type, id == 1);
                debug_assert!(next_block_num >= tx.block_num);
                let end_inner_block_steps = (tx.block_num..next_block_num)
                    .map(|block_num| ExecStep {
                        rw_counter: rwc,
                        execution_state: ExecutionState::EndInnerBlock,
                        block_num,
                        ..Default::default()
                    })
                    .collect::<Vec<ExecStep>>();
                log::trace!("end_inner_block_steps {:?}", end_inner_block_steps);
                end_inner_block_steps
            })
            .collect(),
    }
}

impl From<&Transaction> for SignedTransaction {
    fn from(tx: &Transaction) -> Self {
        Self {
            tx: tx.clone(),
            signature: Signature {
                v: tx.v,
                r: tx.r,
                s: tx.s,
            },
        }
    }
}
