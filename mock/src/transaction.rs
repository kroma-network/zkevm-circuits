//! Mock Transaction definition and builder related methods.

use super::{test_ctx::SYSTEM_DEPOSIT_TX_GAS, MOCK_ACCOUNTS, MOCK_CHAIN_ID, MOCK_GASPRICE};
use eth_types::{
    address,
    geth_types::{Transaction as GethTransaction, TxType, DEPOSIT_TX_TYPE},
    kroma_params::{L1_BLOCK, SYSTEM_TX_CALLER},
    word, AccessList, Address, Bytes, Hash, Transaction, Word, U64,
};
#[cfg(not(feature = "kroma"))]
use ethers_core::types::OtherFields;
use ethers_core::{
    rand::{CryptoRng, RngCore},
    types::TransactionRequest,
    utils::hex,
};
use ethers_signers::{LocalWallet, Signer};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::str::FromStr;

lazy_static! {
    /// Collection of correctly hashed and signed Transactions which can be used to test circuits or opcodes that have to check integrity of the Tx itself.
    /// Some of the parameters of the Tx are hardcoded such as `nonce`, `value`, `gas_price` etc...
    pub static ref CORRECT_MOCK_TXS: Vec<MockTransaction> = {
        let mut rng = ChaCha20Rng::seed_from_u64(2u64);

        vec![
            MockTransaction::default()
                .transaction_idx(1u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[0])
                .nonce(0x103u64)
                .value(word!("0x3e8"))
                .gas_price(word!("0x4d2"))
                .input(vec![1, 2, 3, 4, 5, 0, 6, 7, 8, 9].into()) // call data gas cost of 0 is 4
                .build(),
            MockTransaction::default()
                .transaction_idx(2u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[1])
                .nonce(0x104u64)
                .value(word!("0x3e8"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b"hello"))
                .build(),
            MockTransaction::default()
                .transaction_idx(3u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[2])
                .nonce(0x105u64)
                .value(word!("0x3e8"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b"hello"))
                .build(),
            MockTransaction::default()
                .transaction_idx(4u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[3])
                .nonce(0x106u64)
                .value(word!("0x3e8"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b""))
                .build(),
            MockTransaction::default()
                .transaction_idx(5u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[4])
                .nonce(0x0u64)
                .value(word!("0x0"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b"hello"))
                .build(),
            MockTransaction::default()
                .transaction_idx(6u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(AddrOrWallet::Addr(Address::zero()))
                .nonce(0x0u64)
                .value(word!("0x0"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b"hello"))
                .build(),
            #[cfg(feature = "kroma")]
            // deposit tx from kroma
            MockTransaction::default()
                .transaction_type(DEPOSIT_TX_TYPE)
                .hash(Hash::from_str("0xba940eddf4c601ec510443b19f31ca3f354f18b844cebda8ce4c43fe5d53fa70").unwrap())
                .transaction_idx(1u64)
                .from(AddrOrWallet::Addr(*SYSTEM_TX_CALLER))
                .to(AddrOrWallet::Addr(*L1_BLOCK))
                .nonce(72u64)
                .value(word!("0x0"))
                .gas(Word::from(SYSTEM_DEPOSIT_TX_GAS))
                .input(
                    hex::decode(
                    "efc674eb\
                    000000000000000000000000000000000000000000000000000000000000001a\
                    0000000000000000000000000000000000000000000000000000000064a50e70\
                    0000000000000000000000000000000000000000000000000000000001e18791\
                    3d0f4db630aef9e4d7a5f94be45dc18820b7cae5602d6f056cd60bc52eb74245\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc\
                    0000000000000000000000000000000000000000000000000000000000000834\
                    00000000000000000000000000000000000000000000000000000000000f4240\
                    00000000000000000000000000000000000000000000000000000000000007d0"
                    ).unwrap().into()
                )
                .mint(word!("0x0"))
                .source_hash(
                    Hash::from_str("0x20bae9fe252823414190884e97a5219704d96df8451ac61e52f8ebe11df4161d").unwrap()
                ).build_kroma(),
            #[cfg(feature = "kroma")]
            // legacy tx from kroma
            MockTransaction::default()
                .transaction_type(0u64)
                .hash(Hash::from_str("0x6e9d05e31c45653dc8c188ce67a0038ce7f8707a44c2add4fe5ba6ce0caec1fa").unwrap())
                .transaction_idx(2u64)
                .from(AddrOrWallet::Addr(address!("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")))
                .to(AddrOrWallet::Addr(address!("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")))
                .nonce(0u64)
                .value(word!("0xde0b6b3a7640000"))
                .gas(word!("0x5208"))
                .gas_price(word!("0x3b9c2b4a"))
                .input(Bytes::from(b""))
                .sig_data(
                    (
                        1837u64,
                        Word::from("0x70e69cab41c0933ab4bbdb43232c23271209770c561681f4118636777232bb3c"),
                        Word::from("0x2d102204d2e8e80177cc9f02b88552e6a6a400b13e8d7b8585603c29b49e4fa8"),
                    )
                )
                .build(),
            // deploy tx from kroma
            MockTransaction::default()
                .hash(Hash::from_str("0x1b384a5effb97623025407c4dcc0e947e7ea4f52f0ed4bf1548db337a6501356").unwrap())
                .nonce(0u64)
                .from(AddrOrWallet::Addr(address!("0xeefca179f40d3b8b3d941e6a13e48835a3af8241")))
                .value(Word::zero())
                .gas(word!("0xf4240"))
                .gas_price(Word::from(1))
                .input(hex::decode("6960606060606060606060600052610014610142f3").unwrap().into())
                .sig_data((
                    2711,
                    Word::from_str("0xabfa2ed41f429e227e7cf9f2e64b3935c1514f39011c43618bc1005d29a41f1d").unwrap(),
                    Word::from_str("0x6d9c6ba0f8c435d79c2016488b52756cc5553b1140a1a11f8b2b4cc4b97cb406").unwrap()
                ))
                .build()
        ]
    };
}

#[derive(Debug, Clone)]
pub enum AddrOrWallet {
    Addr(Address),
    Wallet(LocalWallet),
}

impl Default for AddrOrWallet {
    fn default() -> Self {
        AddrOrWallet::Addr(Address::default())
    }
}

impl From<Address> for AddrOrWallet {
    fn from(addr: Address) -> Self {
        AddrOrWallet::Addr(addr)
    }
}

impl From<LocalWallet> for AddrOrWallet {
    fn from(wallet: LocalWallet) -> Self {
        AddrOrWallet::Wallet(wallet)
    }
}

impl AddrOrWallet {
    /// Generates a random Wallet from a random secpk256 keypair
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        AddrOrWallet::Wallet(LocalWallet::new(rng))
    }
}

impl AddrOrWallet {
    /// Returns the underlying address associated to the `AddrOrWallet` enum.
    pub fn address(&self) -> Address {
        match self {
            Self::Addr(addr) => *addr,
            Self::Wallet(wallet) => wallet.address(),
        }
    }

    /// Returns true if the enum variant of `self` corresponds to a
    /// [`LocalWallet`] structure and not simply and [`Address`].
    const fn is_wallet(&self) -> bool {
        matches!(self, Self::Wallet(_))
    }

    /// Returns the underlying wallet stored in the enum.
    /// # Panics
    /// This function will panic if the enum does not contain a [`LocalWallet`]
    /// and instead contains the [`Address`] variant.
    pub fn as_wallet(&self) -> LocalWallet {
        match self {
            Self::Wallet(wallet) => wallet.to_owned(),
            _ => panic!("Broken AddrOrWallet invariant"),
        }
    }
}

#[derive(Debug, Clone)]
/// Mock structure which represents a Transaction and can be used for tests.
/// It contains all the builder-pattern methods required to be able to specify
/// any of it's details.
pub struct MockTransaction {
    pub hash: Option<Hash>,
    pub nonce: u64,
    pub block_hash: Hash,
    pub block_number: U64,
    pub transaction_index: U64,
    pub from: AddrOrWallet,
    pub to: Option<AddrOrWallet>,
    pub value: Word,
    pub gas_price: Word,
    pub gas: Word,
    pub input: Bytes,
    pub v: Option<U64>,
    pub r: Option<Word>,
    pub s: Option<Word>,
    pub transaction_type: TxType,
    pub access_list: AccessList,
    pub max_priority_fee_per_gas: Word,
    pub max_fee_per_gas: Word,
    pub chain_id: u64,

    /// Kroma deposit tx.
    #[cfg(feature = "kroma")]
    pub mint: Word,
    /// Kroma deposit tx.
    #[cfg(feature = "kroma")]
    pub source_hash: Hash,
}

impl Default for MockTransaction {
    fn default() -> Self {
        MockTransaction {
            hash: None,
            nonce: 0,
            block_hash: Hash::zero(),
            block_number: U64::zero(),
            transaction_index: U64::zero(),
            from: AddrOrWallet::Addr(MOCK_ACCOUNTS[0]),
            to: None,
            value: Word::zero(),
            gas_price: *MOCK_GASPRICE,
            gas: Word::from(1_000_000u64),
            input: Bytes::default(),
            v: None,
            r: None,
            s: None,
            transaction_type: TxType::default(),
            access_list: AccessList::default(),
            max_priority_fee_per_gas: Word::zero(),
            max_fee_per_gas: Word::zero(),
            chain_id: *MOCK_CHAIN_ID,
            #[cfg(feature = "kroma")]
            mint: Word::zero(),
            #[cfg(feature = "kroma")]
            source_hash: Hash::zero(),
        }
    }
}

impl From<&MockTransaction> for Transaction {
    fn from(mock: &MockTransaction) -> Self {
        let mut tx = Transaction {
            hash: mock.hash.unwrap_or_default(),
            nonce: mock.nonce.into(),
            block_hash: Some(mock.block_hash),
            block_number: Some(mock.block_number),
            transaction_index: Some(mock.transaction_index),
            from: mock.from.address(),
            to: mock.to.as_ref().map(|addr| addr.address()),
            value: mock.value,
            gas_price: Some(mock.gas_price),
            gas: mock.gas,
            input: mock.input.clone(),
            v: mock.v.unwrap_or_default(),
            r: mock.r.unwrap_or_default(),
            s: mock.s.unwrap_or_default(),
            transaction_type: Some(U64::from(mock.transaction_type.to_value())),
            access_list: Some(mock.access_list.clone()),
            max_priority_fee_per_gas: Some(mock.max_priority_fee_per_gas),
            max_fee_per_gas: Some(mock.max_fee_per_gas),
            chain_id: Some(mock.chain_id.into()),
            #[cfg(feature = "kroma")]
            other: Default::default(),
            #[cfg(not(feature = "kroma"))]
            other: OtherFields::default(),
        };

        #[cfg(feature = "kroma")]
        if let Some(tx_type) = tx.transaction_type {
            if tx_type == U64::from(DEPOSIT_TX_TYPE) {
                let mint = mock.mint;
                let source_hash = mock.source_hash;

                let mint_json_string = format!("\"mint\": \"{mint:#?}\"");
                let source_hash_json_string = format!("\"sourceHash\": \"{source_hash:#?}\"");
                let json_value = format!("{{{mint_json_string}, {source_hash_json_string}}}");
                tx.other = serde_json::from_str(json_value.as_str()).unwrap();
            }
        }
        tx
    }
}

impl From<&MockTransaction> for GethTransaction {
    fn from(mock: &MockTransaction) -> Self {
        GethTransaction::from(&Transaction::from(mock))
    }
    // fn from(mock: &MockTransaction) -> Self {
    //     Self {
    //         tx_type: mock.transaction_type,
    //         from: mock.from.address(),
    //         to: mock.to.as_ref().map(|addr| addr.address()),
    //         nonce: Word::from(mock.nonce),
    //         gas_limit: mock.gas,
    //         value: mock.value,
    //         gas_price: mock.gas_price,
    //         gas_fee_cap: Word::default(),
    //         gas_tip_cap: Word::default(),
    //         call_data: mock.input.clone(),
    //         access_list: Some(mock.access_list.clone()),
    //         v: match mock.v {
    //             Some(v) => v.as_u64(),
    //             None => U64::default().as_u64(),
    //         },
    //         r: match mock.r {
    //             Some(r) => r,
    //             None => Word::default(),
    //         },
    //         s: match mock.s {
    //             Some(s) => s,
    //             None => Word::default(),
    //         },
    //         rlp_bytes: mock.
    //         hash: match mock.hash {
    //             Some(hash) => hash,
    //             None => panic!("mock_transaction without tx_hash not allowed"),
    //         },
    //         #[cfg(feature = "kroma")]
    //         mint: mock.mint,
    //         #[cfg(feature = "kroma")]
    //         source_hash: mock.source_hash,
    //         #[cfg(feature = "kroma")]
    //         rollup_data_gas_cost: match mock.transaction_type {
    //             TxType::L1Msg => 0,
    //             _ => {
    //
    // GethTransaction::compute_rollup_data_gas_cost(&Transaction::from(mock.clone()))
    //             }
    //         },
    //     }
    // }
}

impl MockTransaction {
    /// Tx Hash computed based on the fields of the Tx by
    /// default unless `Some(hash)` is specified on build process.
    pub fn hash(&mut self, hash: Hash) -> &mut Self {
        self.hash = Some(hash);
        self
    }

    /// Set nonce field for the MockTransaction.
    pub fn nonce(&mut self, nonce: u64) -> &mut Self {
        self.nonce = nonce;
        self
    }

    /// Set block_hash field for the MockTransaction.
    pub fn block_hash(&mut self, block_hash: Hash) -> &mut Self {
        self.block_hash = block_hash;
        self
    }

    /// Set block_number field for the MockTransaction.
    pub fn block_number(&mut self, block_number: u64) -> &mut Self {
        self.block_number = U64::from(block_number);
        self
    }

    /// Set transaction_idx field for the MockTransaction.
    pub fn transaction_idx(&mut self, transaction_idx: u64) -> &mut Self {
        self.transaction_index = U64::from(transaction_idx);
        self
    }

    /// Set from field for the MockTransaction.
    pub fn from<T: Into<AddrOrWallet>>(&mut self, from: T) -> &mut Self {
        self.from = from.into();
        self
    }

    /// Set to field for the MockTransaction.
    pub fn to<T: Into<AddrOrWallet>>(&mut self, to: T) -> &mut Self {
        self.to = Some(to.into());
        self
    }

    /// Set value field for the MockTransaction.
    pub fn value(&mut self, value: Word) -> &mut Self {
        self.value = value;
        self
    }

    /// Set gas_price field for the MockTransaction.
    pub fn gas_price(&mut self, gas_price: Word) -> &mut Self {
        self.gas_price = gas_price;
        self
    }

    /// Set gas field for the MockTransaction.
    pub fn gas(&mut self, gas: Word) -> &mut Self {
        self.gas = gas;
        self
    }

    /// Set input field for the MockTransaction.
    pub fn input(&mut self, input: Bytes) -> &mut Self {
        self.input = input;
        self
    }

    /// Set sig_data field for the MockTransaction.
    pub fn sig_data(&mut self, data: (u64, Word, Word)) -> &mut Self {
        self.v = Some(U64::from(data.0));
        self.r = Some(data.1);
        self.s = Some(data.2);
        self
    }

    /// Set transaction_type field for the MockTransaction.
    pub fn transaction_type(&mut self, transaction_type: u64) -> &mut Self {
        // get tx type by value with dummy v.
        self.transaction_type = TxType::get_tx_type_by_value(transaction_type, 100);
        self
    }

    /// Set access_list field for the MockTransaction.
    pub fn access_list(&mut self, access_list: AccessList) -> &mut Self {
        self.access_list = access_list;
        self
    }

    /// Set max_priority_fee_per_gas field for the MockTransaction.
    pub fn max_priority_fee_per_gas(&mut self, max_priority_fee_per_gas: Word) -> &mut Self {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas;
        self
    }

    /// Set max_fee_per_gas field for the MockTransaction.
    pub fn max_fee_per_gas(&mut self, max_fee_per_gas: Word) -> &mut Self {
        self.max_fee_per_gas = max_fee_per_gas;
        self
    }

    /// Set chain_id field for the MockTransaction.
    pub fn chain_id(&mut self, chain_id: u64) -> &mut Self {
        self.chain_id = chain_id;
        self
    }

    #[cfg(feature = "kroma")]
    /// Set mint field for the MockTransaction.
    pub fn mint(&mut self, mint: Word) -> &mut Self {
        self.mint = mint;
        self
    }

    #[cfg(feature = "kroma")]
    /// Set source hash field for the MockTransaction.
    pub fn source_hash(&mut self, source_hash: Hash) -> &mut Self {
        self.source_hash = source_hash;
        self
    }

    /// Consumes the mutable ref to the MockTransaction returning the structure
    /// by value.
    pub fn build(&mut self) -> Self {
        let tx = TransactionRequest::new()
            .from(self.from.address())
            .to(self.to.clone().unwrap_or_default().address())
            .nonce(self.nonce)
            .value(self.value)
            .data(self.input.clone())
            .gas(self.gas)
            .gas_price(self.gas_price)
            .chain_id(U64::from(self.chain_id));

        match (self.v, self.r, self.s) {
            (None, None, None) => {
                // Compute sig params and set them in case we have a wallet as `from` attr.
                if self.from.is_wallet() && self.hash.is_none() {
                    let sig = self
                        .from
                        .as_wallet()
                        .with_chain_id(self.chain_id)
                        .sign_transaction_sync(&tx.into());
                    // Set sig parameters
                    self.sig_data((sig.v, sig.r, sig.s));
                }
            }
            (Some(_), Some(_), Some(_)) => (),
            _ => panic!("either all or none of the SigData params have to be set"),
        }

        // Compute tx hash in case is not already set
        if self.hash.is_none() {
            // let tx= (&*self);
            let tmp_tx = Transaction::from(&*self);
            // FIXME: Note that tmp_tx does not have sigs if self.from.is_wallet() = false.
            //  This means tmp_tx.hash() is not correct.
            self.hash(tmp_tx.hash());
        }

        self.to_owned()
    }

    #[cfg(feature = "kroma")]
    pub fn build_kroma(&mut self) -> Self {
        match (self.v, self.r, self.s) {
            (None, None, None) => {
                self.v = Some(U64::zero());
                self.r = Some(Word::zero());
                self.s = Some(Word::zero());
            }
            (Some(_), Some(_), Some(_)) => (),
            _ => panic!("either all or none of the SigData params have to be set"),
        }

        if self.hash.is_none() {
            panic!("mock_transaction without tx_hash not allowed")
        }
        self.to_owned()
    }
}
