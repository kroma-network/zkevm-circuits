//! Types needed for generating Ethereum traces

use crate::{
    sign_types::{biguint_to_32bytes_le, ct_option_ok_or, recover_pk, SignData, SECP256K1_Q},
    AccessList, Address, Block, Bytes, Error, GethExecTrace, Hash, ToBigEndian, ToLittleEndian,
    Word, U64,
};
use ethers_core::{
    types::{NameOrAddress, TransactionRequest, H256},
    utils::rlp::RlpStream,
};
use ethers_signers::{LocalWallet, Signer};
use halo2_proofs::halo2curves::{group::ff::PrimeField, secp256k1};
use num::Integer;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize, Serializer};
use serde_with::serde_as;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, str::FromStr};

#[cfg(feature = "kroma")]
/// Kroma deposit transaction type
pub const DEPOSIT_TX_TYPE: u64 = 0x7e;

/// Definition of all of the data related to an account.
#[serde_as]
#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize)]
pub struct Account {
    /// Address
    pub address: Address,
    /// nonce
    /// U64 type is required to serialize into proper hex with 0x prefix
    pub nonce: U64,
    /// Balance
    pub balance: Word,
    /// EVM Code
    pub code: Bytes,
    /// Storage
    #[serde(serialize_with = "serde_account_storage")]
    pub storage: HashMap<Word, Word>,
}

impl Account {
    /// Return if account is empty or not.
    pub fn is_empty(&self) -> bool {
        self.nonce.is_zero()
            && self.balance.is_zero()
            && self.code.is_empty()
            && self.storage.is_empty()
    }
}

fn serde_account_storage<S: Serializer>(
    to_serialize: &HashMap<Word, Word>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    to_serialize
        .iter()
        .map(|(k, v)| (Hash::from(k.to_be_bytes()), Hash::from(v.to_be_bytes())))
        .collect::<HashMap<_, _>>()
        .serialize(serializer)
}

/// Definition of all of the constants related to an Ethereum block and
/// chain to be used as setup for the external tracer.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct BlockConstants {
    /// coinbase
    pub coinbase: Address,
    /// time
    pub timestamp: Word,
    /// number
    pub number: U64,
    /// difficulty
    pub difficulty: Word,
    /// gas limit
    pub gas_limit: Word,
    /// base fee
    pub base_fee: Word,
}

impl<TX> TryFrom<&Block<TX>> for BlockConstants {
    type Error = Error;

    fn try_from(block: &Block<TX>) -> Result<Self, Self::Error> {
        Ok(Self {
            coinbase: block.author.ok_or(Error::IncompleteBlock)?,
            timestamp: block.timestamp,
            number: block.number.ok_or(Error::IncompleteBlock)?,
            difficulty: block.difficulty,
            gas_limit: block.gas_limit,
            base_fee: block.base_fee_per_gas.ok_or(Error::IncompleteBlock)?,
        })
    }
}

impl BlockConstants {
    /// Generates a new `BlockConstants` instance from it's fields.
    pub fn new(
        coinbase: Address,
        timestamp: Word,
        number: U64,
        difficulty: Word,
        gas_limit: Word,
        base_fee: Word,
    ) -> BlockConstants {
        BlockConstants {
            coinbase,
            timestamp,
            number,
            difficulty,
            gas_limit,
            base_fee,
        }
    }
}

/// Definition of all of the constants related to an Ethereum transaction.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type
    pub transaction_type: Option<U64>,
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Transaction nonce
    pub nonce: Word,
    /// Gas Limit / Supplied gas
    pub gas_limit: Word,
    /// Transferred value
    pub value: Word,
    /// Gas Price
    pub gas_price: Word,
    /// Gas fee cap
    pub gas_fee_cap: Word,
    /// Gas tip cap
    pub gas_tip_cap: Word,
    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see
    /// Ethereum Contract ABI
    pub call_data: Bytes,
    /// Access list
    pub access_list: Option<AccessList>,

    /// "v" value of the transaction signature
    pub v: u64,
    /// "r" value of the transaction signature
    pub r: Word,
    /// "s" value of the transaction signature
    pub s: Word,

    /// Transaction hash
    pub hash: H256,
    /// Kroma Deposit tx
    #[cfg(feature = "kroma")]
    /// Mint
    pub mint: Word,
    #[cfg(feature = "kroma")]
    /// Source Hash
    pub source_hash: H256,

    /// Kroma Non-deposit tx
    #[cfg(feature = "kroma")]
    /// Rollup data gas cost
    pub rollup_data_gas_cost: u64,
}

/// Casting `GethTransaction` to `Transaction` for response
impl From<&Transaction> for ethers_core::types::Transaction {
    fn from(tx: &Transaction) -> crate::Transaction {
        crate::Transaction {
            transaction_type: tx.transaction_type,
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce,
            gas: tx.gas_limit,
            value: tx.value,
            gas_price: Some(tx.gas_price),
            max_priority_fee_per_gas: Some(tx.gas_fee_cap),
            max_fee_per_gas: Some(tx.gas_tip_cap),
            input: tx.call_data.clone(),
            access_list: tx.access_list.clone(),
            v: tx.v.into(),
            r: tx.r,
            s: tx.s,
            hash: tx.hash,
            ..Default::default()
        }
    }
}

/// Casting `Transaction` for response to `GethTransaction`
impl From<&ethers_core::types::Transaction> for Transaction {
    fn from(tx: &crate::Transaction) -> Transaction {
        Transaction {
            transaction_type: tx.transaction_type,
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce,
            gas_limit: tx.gas,
            value: tx.value,
            gas_price: tx.gas_price.unwrap_or_default(),
            gas_fee_cap: tx.max_priority_fee_per_gas.unwrap_or_default(),
            gas_tip_cap: tx.max_fee_per_gas.unwrap_or_default(),
            call_data: tx.input.clone(),
            access_list: tx.access_list.clone(),
            v: tx.v.as_u64(),
            r: tx.r,
            s: tx.s,
            hash: tx.hash,
            #[cfg(feature = "kroma")]
            mint: Transaction::get_mint(tx).unwrap_or_default(),
            #[cfg(feature = "kroma")]
            source_hash: Transaction::get_source_hash(tx).unwrap_or_default(),
            #[cfg(feature = "kroma")]
            rollup_data_gas_cost: Transaction::compute_rollup_data_gas_cost(tx),
        }
    }
}

/// Casting `GethTransaction` to `TransactionRequest`
impl From<&Transaction> for TransactionRequest {
    fn from(tx: &Transaction) -> TransactionRequest {
        TransactionRequest {
            from: Some(tx.from),
            to: tx.to.map(NameOrAddress::Address),
            gas: Some(tx.gas_limit),
            gas_price: Some(tx.gas_price),
            value: Some(tx.value),
            data: Some(tx.call_data.clone()),
            nonce: Some(tx.nonce),
            ..Default::default()
        }
    }
}

impl Transaction {
    /// Retrieve mint from `Transaction.other`.
    pub fn get_mint(tx: &ethers_core::types::Transaction) -> Option<Word> {
        tx.other
            .get("mint")
            .map(|v| Word::from_str(v.as_str().unwrap()).unwrap())
    }

    /// Retrieve source hash from `Transaction.other`.
    pub fn get_source_hash(tx: &ethers_core::types::Transaction) -> Option<H256> {
        tx.other
            .get("sourceHash")
            .map(|v| H256::from_str(v.as_str().unwrap()).unwrap())
    }

    /// Compute rollup data gas cost from `ResponseTransaction`
    pub fn compute_rollup_data_gas_cost(tx: &crate::Transaction) -> u64 {
        let data = tx.rlp();
        let mut zeros = 0;
        let mut non_zeros = 0;
        data.iter()
            .for_each(|x| if *x == 0 { zeros += 1 } else { non_zeros += 1 });
        zeros * 4 + non_zeros * 16
    }

    /// Whether this Transaction is a deposit transaction.
    pub fn is_deposit(&self) -> bool {
        #[cfg(feature = "kroma")]
        return self.transaction_type.unwrap_or_default().as_u64() == DEPOSIT_TX_TYPE;
        #[cfg(not(feature = "kroma"))]
        return false;
    }

    #[cfg(feature = "kroma")]
    /// Return rlp encoded bytes which is used to sign tx.
    pub fn rlp_unsigned<T: Into<U64>>(&self, chain_id: T) -> Bytes {
        match self.transaction_type.unwrap_or_default().as_u64() {
            0 | 1 | 2 => {
                let mut legacy_tx = TransactionRequest::new()
                    .from(self.from)
                    .nonce(self.nonce)
                    .gas_price(self.gas_price)
                    .gas(self.gas_limit)
                    .value(self.value)
                    .data(self.call_data.clone())
                    .chain_id(chain_id);
                if self.to.is_some() {
                    legacy_tx = legacy_tx.to(NameOrAddress::Address(self.to.unwrap()));
                }

                legacy_tx.rlp()
            }
            DEPOSIT_TX_TYPE => {
                // NOTE(dongchangYoo): For deposit transactions, this function returns a byte array
                // equivalent to the output of rlp_signed(). Even though the returned bytes are not
                // used for transaction signing, they still need to conform to the rlp-circuit rule.
                self.rlp_signed()
            }
            _ => panic!("not supported transaction type"),
        }
    }

    #[cfg(feature = "kroma")]
    /// Return rlp encoded bytes which is used to calculate transaction hash
    pub fn rlp_signed(&self) -> Bytes {
        let tx_type = self.transaction_type.unwrap_or_default().as_u64();
        match tx_type {
            0 | 1 | 2 => {
                let mut legacy_tx = TransactionRequest::new()
                    .from(self.from)
                    .nonce(self.nonce)
                    .gas_price(self.gas_price)
                    .gas(self.gas_limit)
                    .value(self.value)
                    .data(self.call_data.clone());
                if self.to.is_some() {
                    legacy_tx = legacy_tx.to(NameOrAddress::Address(self.to.unwrap()));
                }

                let sig = ethers_core::types::Signature {
                    r: self.r,
                    s: self.s,
                    v: self.v,
                };

                legacy_tx.rlp_signed(&sig)
            }
            #[cfg(feature = "kroma")]
            DEPOSIT_TX_TYPE => {
                let mut s = RlpStream::new();

                s.append(&tx_type);

                s.begin_list(7);
                s.append(&self.source_hash);
                s.append(&self.from);
                if self.to.is_some() {
                    s.append(&self.to.unwrap());
                } else {
                    s.append(&"");
                }
                s.append(&self.mint);
                s.append(&self.value);
                s.append(&self.gas_limit);
                s.append(&self.call_data.to_vec());

                s.out().freeze().into()
            }
            _ => panic!("not supported transaction type"),
        }
    }

    /// Return the SignData associated with this Transaction.
    pub fn sign_data(&self, chain_id: u64) -> Result<SignData, Error> {
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
        let msg = self.rlp_unsigned(chain_id);
        let msg_hash: [u8; 32] = Keccak256::digest(&msg)
            .as_slice()
            .to_vec()
            .try_into()
            .expect("hash length isn't 32 bytes");
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
}

/// GethData is a type that contains all the information of a Ethereum block
#[derive(Debug, Clone)]
pub struct GethData {
    /// chain id
    pub chain_id: Word,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block from geth
    pub eth_block: Block<crate::Transaction>,
    /// Execution Trace from geth
    pub geth_traces: Vec<GethExecTrace>,
    /// Accounts
    pub accounts: Vec<Account>,
}

impl GethData {
    /// Signs transactions with selected wallets
    pub fn sign(&mut self, wallets: &HashMap<Address, LocalWallet>) {
        for tx in self.eth_block.transactions.iter_mut() {
            #[cfg(feature = "kroma")]
            if tx.transaction_type == Some(U64::from(DEPOSIT_TX_TYPE)) {
                continue;
            }
            let wallet = wallets.get(&tx.from).unwrap();
            assert_eq!(Word::from(wallet.chain_id()), self.chain_id);
            let geth_tx: Transaction = (&*tx).into();
            let req: TransactionRequest = (&geth_tx).into();
            let sig = wallet.sign_transaction_sync(&req.chain_id(self.chain_id.as_u64()).into());
            tx.v = U64::from(sig.v);
            tx.r = sig.r;
            tx.s = sig.s;
            // The previous tx.hash is calculated without signature.
            // Therefore we need to update tx.hash.
            tx.hash = tx.hash();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        geth_types::Transaction,
        sign_types::{pk_bytes_le, pk_bytes_swap_endianness, recover_pk},
    };
    use ethers_core::utils::keccak256;

    pub const CHAIN_ID: u64 = 901;

    #[test]
    #[cfg(feature = "kroma")]
    fn deposit_tx_rlp_test() {
        let deposit_tx_raw = r#"{
            "transaction_type": "0x7e",
            "from": "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001",
			"to": "0x4200000000000000000000000000000000000002",
            "nonce": "0xa",
            "gas_limit": "0xf4240",
            "value": "0x0",
            "gas_price": "0x0",
            "gas_fee_cap": "0x0",
            "gas_tip_cap": "0x0",
            "call_data": "0xefc674eb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000064a66605000000000000000000000000000000000000000000000000000000003b9aca00e121af8dafefbd3429a259370c4393d3d3f9649c82e70456713396c17a8e5e67000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f424000000000000000000000000000000000000000000000000000000000000007d0",
            "access_list": [],
            "v": 0,
			"r": "0x0",
			"s": "0x0",
            "hash": "0xba940eddf4c601ec510443b19f31ca3f354f18b844cebda8ce4c43fe5d53fa70",
            "mint": "0x0",
            "source_hash": "0xf829b378897e49c91f6a99693364c0d290c3d5291c2784118d046ec7ddee268b",
            "rollup_data_gas_cost": 0
        }"#;

        let deposit_tx: Transaction = serde_json::from_str(deposit_tx_raw).unwrap();

        let rlp_signed = deposit_tx.rlp_signed();
        let rlp_unsigned = deposit_tx.rlp_unsigned(CHAIN_ID);

        // In case of deposit tx, it holds (dummy rlp_unsigned)
        assert_eq!(rlp_signed, rlp_unsigned);

        let tx_hash = keccak256(rlp_signed);
        assert_eq!(
            hex::encode(tx_hash),
            "09d8409de0d191d50a599d21c6ddbff4cdb8b3ecde3702c0bdf5ddda50532f7a"
        );
    }

    #[test]
    #[cfg(feature = "kroma")]
    fn legacy_tx_rlp_test() {
        let legacy_tx_raw = r#"{
            "transaction_type": "0x0",
            "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			"to": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "nonce": "0x0",
            "gas_limit": "0x5208",
            "value": "0xde0b6b3a7640000",
            "gas_price": "0x3d7b51db",
            "gas_fee_cap": "0x0",
            "gas_tip_cap": "0x0",
            "call_data": "",
            "access_list": [],
            "v": 1837,
			"r": "0xec98d5757fb5c2a5622957bec95460221a12de528030aba9951323a1a7a8f7a6",
			"s": "0x5df7b45225a4dbf0ebcbb056d6affab41f69812f2d5e5c399ec013700b2d4753",
            "hash": "0x641c4cfd56f152d7ebd6a6a85cea8e98d1487c69a00aad606b28c6f225d06c8d",
            "source_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "mint": "0x0",
            "rollup_data_gas_cost": 0
        }"#;

        let kroma_tx: Transaction = serde_json::from_str(legacy_tx_raw).unwrap();

        let rlp_signed = kroma_tx.rlp_signed();
        let tx_hash = keccak256(rlp_signed);
        assert_eq!(hex::encode(tx_hash), hex::encode(kroma_tx.hash));

        let rlp_unsigned = kroma_tx.rlp_unsigned(CHAIN_ID);
        let msg_hash = keccak256(rlp_unsigned);
        let recover_id = ((kroma_tx.v + 1) % 2) as u8;

        let pk = recover_pk(recover_id, &kroma_tx.r, &kroma_tx.s, &msg_hash).unwrap();
        let pk_le = pk_bytes_le(&pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        let pk_hash = keccak256(pk_be);
        assert_eq!(hex::encode(&pk_hash[12..]), hex::encode(kroma_tx.from));
    }
}
