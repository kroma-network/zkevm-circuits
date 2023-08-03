use super::{step::step_convert, Call, ExecStep};
use crate::{
    evm_circuit::{step::ExecutionState, util::rlc},
    table::TxContextFieldTag,
    util::{rlc_be_bytes, Challenges},
    witness::{
        rlp_fsm::SmState,
        DataTable, Format,
        Format::{
            TxHashDeposit, TxHashEip155, TxHashEip1559, TxHashPreEip155, TxSignEip155,
            TxSignEip1559, TxSignPreEip155,
        },
        RlpFsmWitnessGen, RlpFsmWitnessRow, RlpTable, RlpTag, State,
        State::DecodeTagStart,
        StateMachine,
        Tag::{EndList, EndVector},
    },
};
use bus_mapping::{
    circuit_input_builder,
    circuit_input_builder::{get_dummy_tx, get_dummy_tx_hash},
};
#[cfg(feature = "kroma")]
use eth_types::geth_types::Transaction as GethTransaction;
use eth_types::{
    evm_types::rwc_util::end_tx_rwc,
    geth_types::TxType,
    sign_types::{biguint_to_32bytes_le, ct_option_ok_or, recover_pk, SignData, SECP256K1_Q},
    Address, Error, Field, Hash, Signature, ToBigEndian, ToLittleEndian, ToScalar, ToWord, Word,
    H256,
};
use ethers_core::utils::keccak256;
use halo2_proofs::{
    circuit::Value,
    halo2curves::{group::ff::PrimeField, secp256k1},
};
use mock::MockTransaction;
use num::Integer;
use num_bigint::BigUint;
use std::{cmp::Ordering, collections::BTreeMap};

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
    pub tx_type: TxType,
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
        return self.tx_type.is_deposit_tx();
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
        let tx_hash_be_bytes = keccak256(&self.rlp_signed);
        let tx_sign_hash_be_bytes = keccak256(&self.rlp_unsigned);
        let source_hash_be_bytes = self.source_hash.to_fixed_bytes();

        let ret = vec![
            // #[cfg(feature = "kroma")]
            // [
            //     Value::known(F::from(self.id as u64)),
            //     Value::known(F::from(TxContextFieldTag::Type as u64)),
            //     Value::known(F::zero()),
            //     Value::known(F::from(self.transaction_type)),
            // ],
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
                Value::known(F::from(TxContextFieldTag::CallDataRLC as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.call_data, challenges.keccak_input()),
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
            // omit TxDataGasCost
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::ChainID as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.chain_id)),
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

    pub(crate) fn gen_rlp_witness<F: Field>(
        &self,
        is_hash: bool,
        challenges: &Challenges<Value<F>>,
    ) -> Vec<RlpFsmWitnessRow<F>> {
        let (rlp_bytes, format) = if is_hash {
            (
                self.rlp_signed.clone(),
                match self.tx_type {
                    TxType::Eip155 => TxHashEip155,
                    TxType::PreEip155 => TxHashPreEip155,
                    TxType::Eip1559 => TxHashEip1559,
                    TxType::Deposit => TxHashDeposit,
                    _ => unreachable!("tx type {:?} not supported", self.tx_type),
                },
            )
        } else {
            (
                self.rlp_unsigned.clone(),
                match self.tx_type {
                    TxType::Eip155 => TxSignEip155,
                    TxType::PreEip155 => TxSignPreEip155,
                    TxType::Eip1559 => TxSignEip1559,
                    _ => unreachable!("tx type {:?} not supported", self.tx_type),
                },
            )
        };

        let tx_id = self.id as u64;
        let mut witness = vec![];
        let rom_table = format.rom_table_rows();
        let keccak_rand = challenges.keccak_input();
        let word_rand = challenges.evm_word();
        let rlp_bytes_rlc = rlp_bytes
            .iter()
            .scan(Value::known(F::zero()), |rlc, &byte| {
                *rlc = *rlc * keccak_rand + Value::known(F::from(byte as u64));

                Some(*rlc)
            })
            .collect::<Vec<_>>();
        let rlp_gas_cost_acc = rlp_bytes
            .iter()
            .scan(Value::known(F::zero()), |acc, &byte| {
                let cost = if byte == 0 { 4 } else { 16 };
                *acc = *acc + Value::known(F::from(cost));

                Some(*acc)
            })
            .collect::<Vec<_>>();
        let mut cur = SmState {
            tag: rom_table[0].tag,
            state: DecodeTagStart,
            tag_idx: 0,
            tag_length: 0,
            tag_value_acc: Value::known(F::zero()),
            byte_idx: 0,
            depth: 0,
        };
        // When we are decoding a vector of element type `t`, at the beginning
        // we actually do not know the next tag is `EndVector` or not. After we
        // parsed the current tag, if the remaining bytes to decode in this layer
        // is zero, then the next tag is `EndVector`.
        let mut cur_rom_row = vec![0];
        let mut remaining_bytes = vec![rlp_bytes.len()];
        let mut witness_table_idx = 0;

        // This map keeps track
        // - the last row in the witness table of each parsed tag,
        // - the row in the rom table of each parsed tag.
        // And this map is used to fill the tag_next column in the witness table
        let mut tag_rom_row_map = BTreeMap::new();
        let mut is_output;
        let mut is_none;
        let mut rlp_tag;
        let mut lb_len = 0;

        loop {
            // default behavior
            is_none = false;
            is_output = false;
            rlp_tag = RlpTag::Tag(cur.tag);

            let mut next = cur.clone();
            match cur.state {
                DecodeTagStart => {
                    if cur.tag.is_end() {
                        // assertions
                        assert_eq!(
                            remaining_bytes
                                .pop()
                                .expect("remaining_bytes shall not be empty"),
                            0
                        );
                        if cur.depth == 1 {
                            assert_eq!(remaining_bytes.len(), 1);
                            assert_eq!(remaining_bytes[0], 0);
                            assert_eq!(cur.byte_idx, rlp_bytes.len() - 1);
                            is_output = true;
                            rlp_tag = RlpTag::RLC;
                        } else if cur.depth == 0 {
                            // emit GasCost
                            is_output = true;
                            rlp_tag = RlpTag::GasCost;
                        }

                        // state transitions
                        // if cur.depth == 0 then we are at the end of decoding
                        if cur.depth > 0 {
                            next.depth = cur.depth - 1;
                        }
                        next.state = DecodeTagStart;
                    } else {
                        let byte_value = rlp_bytes[cur.byte_idx];
                        if let Some(rem) = remaining_bytes.last_mut() {
                            // read one more byte
                            assert!(*rem >= 1);
                            *rem -= 1;
                        }
                        if byte_value < 0x80 {
                            // assertions
                            assert!(!cur.tag.is_list());
                            is_output = true;
                            cur.tag_value_acc = Value::known(F::from(byte_value as u64));

                            // state transitions
                            next.state = DecodeTagStart;
                        } else if byte_value == 0x80 {
                            // assertions
                            assert!(!cur.tag.is_list());
                            is_output = true;
                            is_none = true;
                            cur.tag_value_acc = Value::known(F::zero());

                            // state transitions
                            next.state = DecodeTagStart;
                        } else if byte_value < 0xb8 {
                            // assertions
                            assert!(!cur.tag.is_list());

                            // state transitions
                            next.tag_idx = 1;
                            next.tag_length = (byte_value - 0x80) as usize;
                            next.tag_value_acc =
                                Value::known(F::from(rlp_bytes[cur.byte_idx + 1] as u64));
                            next.state = State::Bytes;
                        } else if byte_value < 0xc0 {
                            // assertions
                            assert!(!cur.tag.is_list());

                            // state transitions
                            next.tag_idx = 1;
                            next.tag_length = (byte_value - 0xb7) as usize;
                            lb_len = rlp_bytes[cur.byte_idx + 1] as usize;
                            next.tag_value_acc = Value::known(F::from(lb_len as u64));
                            next.state = State::LongBytes;
                        } else if byte_value < 0xf8 {
                            // assertions
                            assert!(cur.tag.is_begin());
                            if cur.depth == 0 {
                                is_output = true;
                                rlp_tag = RlpTag::Len;
                            }
                            cur.tag_value_acc = Value::known(F::from(u64::from(byte_value - 0xc0)));

                            // state transitions
                            let num_bytes_of_new_list = usize::from(byte_value - 0xc0);
                            if let Some(rem) = remaining_bytes.last_mut() {
                                // Since we are going to decode a new list inside current list,
                                // after that the remaining bytes of
                                // current list should be subtracted by
                                // the number of bytes of the new list.
                                assert!(*rem >= num_bytes_of_new_list);
                                *rem -= num_bytes_of_new_list;
                            }
                            remaining_bytes.push(num_bytes_of_new_list);
                            next.depth = cur.depth + 1;
                            next.state = DecodeTagStart;
                        } else {
                            // assertions
                            assert!(cur.tag.is_begin());
                            // TODO: assert first leading byte is non-zero

                            // state transitions
                            next.tag_idx = 1;
                            next.tag_length = (byte_value - 0xf7) as usize;
                            lb_len = rlp_bytes[cur.byte_idx + 1] as usize;
                            next.tag_value_acc = Value::known(F::from(lb_len as u64));
                            next.state = State::LongList;
                        }
                    }
                }
                State::Bytes => {
                    if let Some(rem) = remaining_bytes.last_mut() {
                        assert!(*rem >= 1);
                        *rem -= 1;
                    }
                    if cur.tag_idx < cur.tag_length {
                        // state transitions
                        let max_length = rom_table[cur_rom_row[0]].max_length;
                        let b = match max_length.cmp(&32) {
                            Ordering::Less => Value::known(F::from(256_u64)),
                            Ordering::Equal => word_rand,
                            Ordering::Greater => keccak_rand,
                        };
                        next.tag_idx = cur.tag_idx + 1;
                        next.tag_value_acc = cur.tag_value_acc * b
                            + Value::known(F::from(rlp_bytes[cur.byte_idx + 1] as u64));
                    } else {
                        // assertions
                        is_output = true;

                        // state transitions
                        next.state = DecodeTagStart;
                    }
                }
                State::LongBytes => {
                    if let Some(rem) = remaining_bytes.last_mut() {
                        assert!(*rem >= 1);
                        *rem -= 1;
                    }

                    if cur.tag_idx < cur.tag_length {
                        // state transitions
                        next.tag_idx = cur.tag_idx + 1;
                        lb_len = lb_len * 256 + usize::from(rlp_bytes[cur.byte_idx + 1]);
                        next.tag_value_acc = Value::known(F::from(lb_len as u64));
                    } else {
                        // we're dealing with case cur.tag_idx == cur.tag_length

                        // state transitions
                        next.tag_idx = 1;
                        next.tag_length = lb_len;
                        next.tag_value_acc =
                            Value::known(F::from(u64::from(rlp_bytes[cur.byte_idx + 1])));
                        next.state = State::Bytes;
                    }
                }
                State::LongList => {
                    if let Some(rem) = remaining_bytes.last_mut() {
                        // read one more byte
                        assert!(*rem >= 1);
                        *rem -= 1;
                    }
                    if cur.tag_idx < cur.tag_length {
                        // state transitions
                        next.tag_idx = cur.tag_idx + 1;
                        lb_len = lb_len * 256 + usize::from(rlp_bytes[cur.byte_idx + 1]);
                        next.tag_value_acc = Value::known(F::from(lb_len as u64));
                    } else {
                        // assertions
                        if cur.depth == 0 {
                            is_output = true;
                            rlp_tag = RlpTag::Len;
                        }
                        if let Some(rem) = remaining_bytes.last_mut() {
                            assert!(*rem >= lb_len);
                            *rem -= lb_len;
                        }
                        remaining_bytes.push(lb_len);
                        next.depth = cur.depth + 1;
                        next.state = DecodeTagStart;
                    }
                }
                State::End => {
                    unreachable!()
                }
            }

            if next.state == DecodeTagStart {
                // we finished parsing current tag
                let row = if cur_rom_row.len() == 1 {
                    cur_rom_row[0]
                } else if cur_rom_row.len() == 2 {
                    // only cur_rom_row[0].tag_next is EndVector.
                    assert_eq!(rom_table[cur_rom_row[0]].tag_next, EndVector);

                    let rem = remaining_bytes.last().expect("");
                    if *rem == 0 {
                        // we have finished parsing the vector.
                        cur_rom_row[0]
                    } else {
                        // we have not finished parsing the vector.
                        cur_rom_row[1]
                    }
                } else {
                    unreachable!()
                };

                assert_eq!(cur.tag, rom_table[row].tag);

                tag_rom_row_map.insert(witness_table_idx, row);
                next.tag = rom_table[row].tag_next;
                cur_rom_row = rom_table[row].tag_next_idx.clone();

                if next.tag.is_end() {
                    // Since the EndList or EndVector tag does not read any byte from the data
                    // table.
                    next.byte_idx = cur.byte_idx;
                } else {
                    next.byte_idx = cur.byte_idx + 1;
                }
            } else {
                // next.state is one of { Bytes, LongBytes, LongList }
                // the sm in these states need to read new byte from data table
                next.byte_idx = cur.byte_idx + 1;
            }

            assert!(cur.byte_idx < rlp_bytes.len());
            let (byte_value, bytes_rlc) = (rlp_bytes[cur.byte_idx], rlp_bytes_rlc[cur.byte_idx]);
            let gas_cost_acc = rlp_gas_cost_acc[cur.byte_idx];

            let tag_value = match rlp_tag {
                RlpTag::Len => cur.tag_value_acc + Value::known(F::from((cur.byte_idx + 1) as u64)),
                RlpTag::RLC => bytes_rlc,
                RlpTag::GasCost => gas_cost_acc,
                RlpTag::Tag(_) => cur.tag_value_acc,
                RlpTag::Null => unreachable!("Null is not used"),
            };

            witness.push(RlpFsmWitnessRow {
                rlp_table: RlpTable {
                    tx_id,
                    format,
                    rlp_tag,
                    tag_value,
                    is_output,
                    is_none,
                },
                state_machine: StateMachine {
                    state: cur.state,
                    tag: cur.tag,
                    max_length: Default::default(), // will be filled up later
                    tag_next: Default::default(),   // will be filled up later
                    byte_idx: cur.byte_idx + 1,
                    byte_rev_idx: rlp_bytes.len() - cur.byte_idx,
                    byte_value,
                    tag_idx: cur.tag_idx,
                    tag_length: cur.tag_length,
                    tag_acc_value: cur.tag_value_acc,
                    depth: cur.depth,
                    bytes_rlc,
                    gas_cost_acc,
                },
            });
            witness_table_idx += 1;

            if cur.tag == EndList && cur.depth == 0 {
                break;
            }
            cur = next;
        }
        // filling up the `tag_next` col of the witness table
        let mut idx = 0;
        for (witness_idx, rom_table_row) in tag_rom_row_map {
            while idx <= witness_idx {
                witness[idx].state_machine.tag_next = rom_table[rom_table_row].tag_next;
                witness[idx].state_machine.max_length = rom_table[rom_table_row].max_length;
                idx += 1;
            }
        }

        witness
    }

    #[cfg(test)]
    pub(crate) fn new_from_rlp_bytes(
        tx_type: TxType,
        signed_bytes: Vec<u8>,
        unsigned_bytes: Vec<u8>,
    ) -> Self {
        Self {
            id: 1,
            tx_type,
            rlp_signed: signed_bytes,
            rlp_unsigned: unsigned_bytes,
            ..Default::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn new_from_rlp_signed_bytes(tx_type: TxType, bytes: Vec<u8>) -> Self {
        Self {
            id: 1,
            tx_type,
            rlp_signed: bytes,
            ..Default::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn new_from_rlp_unsigned_bytes(tx_type: TxType, bytes: Vec<u8>) -> Self {
        Self {
            id: 1,
            tx_type,
            rlp_unsigned: bytes,
            ..Default::default()
        }
    }
}

impl<F: Field> RlpFsmWitnessGen<F> for Transaction {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<RlpFsmWitnessRow<F>> {
        let hash_wit = self.gen_rlp_witness(true, challenges);
        let sign_wit = match self.tx_type {
            TxType::Deposit => vec![],
            _ => self.gen_rlp_witness(false, challenges),
        };

        log::debug!(
            "{}th tx sign witness rows len = {}",
            self.id,
            sign_wit.len()
        );
        log::debug!(
            "{}th tx hash witness rows len = {}",
            self.id,
            hash_wit.len()
        );

        [sign_wit, hash_wit].concat()
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<DataTable<F>> {
        let tx_id = self.id as u64;
        let r = challenges.keccak_input();

        let (hash_format, sign_format) = match self.tx_type {
            TxType::Eip155 => (TxHashEip155, Some(TxSignEip155)),
            TxType::PreEip155 => (TxHashPreEip155, Some(TxSignPreEip155)),
            TxType::Eip1559 => (TxHashEip1559, Some(TxSignEip1559)),
            TxType::Eip2930 => {
                unimplemented!("eip2930 not supported now")
            }
            TxType::Deposit => (TxHashDeposit, None),
        };

        let get_table = |rlp_bytes: &Vec<u8>, format: Format| {
            let n = rlp_bytes.len();
            rlp_bytes
                .iter()
                .enumerate()
                .scan(
                    (Value::known(F::zero()), Value::known(F::zero())),
                    |(rlc, gas_cost_acc), (i, &byte_value)| {
                        let byte_cost = if byte_value == 0 { 4 } else { 16 };
                        *rlc = *rlc * r + Value::known(F::from(byte_value as u64));
                        *gas_cost_acc = *gas_cost_acc + Value::known(F::from(byte_cost));
                        Some(DataTable {
                            tx_id,
                            format,
                            byte_idx: i + 1,
                            byte_rev_idx: n - i,
                            byte_value,
                            bytes_rlc: *rlc,
                            gas_cost_acc: *gas_cost_acc,
                        })
                    },
                )
                .collect::<Vec<_>>()
        };

        let hash_table = get_table(&self.rlp_signed, hash_format);
        if let Some(sign_format) = sign_format {
            let sign_table = get_table(&self.rlp_unsigned, sign_format);
            [sign_table, hash_table].concat()
        } else {
            hash_table
        }
    }
}

// impl Encodable for Transaction {
//     fn rlp_append(&self, s: &mut RlpStream) {
//         match self.transaction_type {
//             0 => {
//                 s.begin_list(9);
//                 s.append(&Word::from(self.nonce));
//                 s.append(&self.gas_price);
//                 s.append(&Word::from(self.gas));
//                 if let Some(addr) = self.callee_address {
//                     s.append(&addr);
//                 } else {
//                     s.append(&"");
//                 }
//                 s.append(&self.value);
//                 s.append(&self.call_data);
//                 s.append(&Word::from(self.chain_id));
//                 s.append(&Word::zero());
//                 s.append(&Word::zero());
//             }
//             #[cfg(feature = "kroma")]
//             DEPOSIT_TX_TYPE => {
//                 s.append(&self.transaction_type);
//                 s.begin_list(7);
//                 s.append(&Word::from(self.source_hash.to_fixed_bytes()));
//                 s.append(&self.caller_address);
//                 if let Some(addr) = self.callee_address {
//                     s.append(&addr);
//                 } else {
//                     s.append(&"");
//                 }
//                 s.append(&self.mint);
//                 s.append(&self.value);
//                 s.append(&self.gas);
//                 s.append(&self.call_data);
//             }
//             _ => panic!("not supported transaction type"),
//         }
//     }
// }
//
// /// Signed transaction in a witness block
// #[derive(Debug, Clone)]
// pub struct SignedTransaction {
//     /// Transaction data.
//     pub tx: Transaction,
//     /// ECDSA signature on the transaction.
//     pub signature: Signature,
// }
//
// impl Encodable for SignedTransaction {
//     fn rlp_append(&self, s: &mut RlpStream) {
//         match self.tx.transaction_type {
//             0 => {
//                 s.begin_list(9);
//                 s.append(&Word::from(self.tx.nonce));
//                 s.append(&self.tx.gas_price);
//                 s.append(&Word::from(self.tx.gas));
//                 if let Some(addr) = self.tx.callee_address {
//                     s.append(&addr);
//                 } else {
//                     s.append(&"");
//                 }
//                 s.append(&self.tx.value);
//                 s.append(&self.tx.call_data);
//                 s.append(&self.signature.v);
//                 s.append(&self.signature.r);
//                 s.append(&self.signature.s);
//             }
//             #[cfg(feature = "kroma")]
//             DEPOSIT_TX_TYPE => {
//                 s.append(&self.tx.transaction_type);
//                 s.begin_list(7);
//                 s.append(&Word::from(self.tx.source_hash.to_fixed_bytes()));
//                 s.append(&self.tx.caller_address);
//                 if let Some(addr) = self.tx.callee_address {
//                     s.append(&addr);
//                 } else {
//                     s.append(&"");
//                 }
//                 s.append(&self.tx.mint);
//                 s.append(&self.tx.value);
//                 s.append(&self.tx.gas);
//                 s.append(&self.tx.call_data);
//             }
//             _ => panic!("not supported transaction type"),
//         }
//     }
// }

impl From<MockTransaction> for Transaction {
    fn from(mock_tx: MockTransaction) -> Self {
        let is_create = mock_tx.to.is_none();
        let sig = Signature {
            r: mock_tx.r.expect("tx expected to be signed"),
            s: mock_tx.s.expect("tx expected to be signed"),
            v: mock_tx.v.expect("tx expected to be signed").as_u64(),
        };
        let geth_tx = GethTransaction::from(&mock_tx);

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
            chain_id: mock_tx.chain_id,
            rlp_unsigned: geth_tx.rlp_unsigned_bytes,
            rlp_signed: geth_tx.rlp_bytes,
            v: sig.v,
            r: sig.r,
            s: sig.s,
            calls: vec![],
            steps: vec![],
            tx_type: mock_tx.transaction_type,
            #[cfg(feature = "kroma")]
            mint: mock_tx.mint,
            #[cfg(feature = "kroma")]
            source_hash: mock_tx.source_hash,
            #[cfg(feature = "kroma")]
            rollup_data_gas_cost: 1000, // TODO(dongchangYoo) FIXME
        }
    }
}
// impl From<MockTransaction> for SignedTransaction {
//     fn from(mock_tx: MockTransaction) -> Self {
//         SignedTransaction::from(&Transaction::from(mock_tx))
//     }
// }

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
    let geth_tx = GethTransaction::from(tx);

    Transaction {
        block_number: tx.block_num,
        id,
        hash: tx.hash, // NOTE that if tx is not of legacy type, then tx.hash does not equal to
        // keccak(rlp_signed)
        tx_type: tx.tx_type,
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
        rlp_unsigned: geth_tx.rlp_unsigned_bytes,
        rlp_signed: geth_tx.rlp_bytes,
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
                    tx.steps().last().unwrap().rwc.0 + end_tx_rwc(tx.tx_type.to_value(), id == 1);
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

// impl From<&Transaction> for SignedTransaction {
//     fn from(tx: &Transaction) -> Self {
//         Self {
//             tx: tx.clone(),
//             signature: Signature {
//                 v: tx.v,
//                 r: tx.r,
//                 s: tx.s,
//             },
//         }
//     }
// }
