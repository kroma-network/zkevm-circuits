//! Mock Transaction definition and builder related methods.

use super::{MOCK_ACCOUNTS, MOCK_CHAIN_ID};
use eth_types::{
    geth_types::Transaction as GethTransaction, word, AccessList, Address, Bytes, Hash,
    Transaction, Word, U64,
};
#[cfg(feature = "kroma")]
use eth_types::{
    address,
    geth_types::DEPOSIT_TX_TYPE,
    kroma_params::{L1_BLOCK, SYSTEM_DEPOSIT_TX_GAS, SYSTEM_TX_CALLER},
}
use ethers_core::{
    rand::{CryptoRng, RngCore},
    types::{Eip1559TransactionRequest, OtherFields, TransactionRequest},
};
#[cfg(feature = "kroma")]
use ethers_core::utils::hex;
use ethers_signers::{LocalWallet, Signer};
use rand::SeedableRng;
use rand_chacha::{rand_core::OsRng, ChaCha20Rng};
use std::sync::LazyLock;

/// Collection of correctly hashed and signed Transactions which can be used to test circuits or
/// opcodes that have to check integrity of the Tx itself. Some of the parameters of the Tx are
/// hardcoded such as `nonce`, `value`, `gas_price` etc...
pub static CORRECT_MOCK_TXS: LazyLock<Vec<MockTransaction>> = LazyLock::new(|| {
    let mut rng = ChaCha20Rng::seed_from_u64(2u64);

    vec![
        MockTransaction::default()
            .transaction_idx(1u64)
            .from(AddrOrWallet::random(&mut rng))
            .to(MOCK_ACCOUNTS[0])
            .nonce(word!("0x103"))
            .value(word!("0x3e8"))
            .gas_price(word!("0x4d2"))
            .input(vec![1, 2, 3, 4, 5, 0, 6, 7, 8, 9].into()) // call data gas cost of 0 is 4
            .build(),
        MockTransaction::default()
            .transaction_idx(2u64)
            .from(AddrOrWallet::random(&mut rng))
            .to(MOCK_ACCOUNTS[1])
            .nonce(word!("0x104"))
            .value(word!("0x3e8"))
            .gas_price(word!("0x4d2"))
            .input(Bytes::from(b"hello"))
            .build(),
        MockTransaction::default()
            .transaction_idx(3u64)
            .from(AddrOrWallet::random(&mut rng))
            .to(MOCK_ACCOUNTS[2])
            .nonce(word!("0x105"))
            .value(word!("0x3e8"))
            .gas_price(word!("0x4d2"))
            .input(Bytes::from(b"hello"))
            .build(),
        MockTransaction::default()
            .transaction_idx(4u64)
            .from(AddrOrWallet::random(&mut rng))
            .to(MOCK_ACCOUNTS[3])
            .nonce(word!("0x106"))
            .value(word!("0x3e8"))
            .gas_price(word!("0x4d2"))
            .input(Bytes::from(b""))
            .build(),
        MockTransaction::default()
            .transaction_idx(5u64)
            .from(AddrOrWallet::random(&mut rng))
            .to(MOCK_ACCOUNTS[4])
            .nonce(word!("0x0"))
            .value(word!("0x0"))
            .gas_price(word!("0x4d2"))
            .input(Bytes::from(b"hello"))
            .build(),
        MockTransaction::default()
            .transaction_idx(6u64)
            .from(AddrOrWallet::random(&mut rng))
            .to(AddrOrWallet::Addr(Address::zero()))
            .nonce(word!("0x0"))
            .value(word!("0x0"))
            .gas_price(word!("0x4d2"))
            .input(Bytes::from(b"hello"))
            .build(),
        #[cfg(feature = "kroma")]
        // Kroma deposit tx
        MockTransaction::default()
            .transaction_type(0x7eu64)
            .hash(
                Hash::from_str(
                    "0xba940eddf4c601ec510443b19f31ca3f354f18b844cebda8ce4c43fe5d53fa70",
                )
                .unwrap(),
            )
            .transaction_idx(1u64)
            .from(AddrOrWallet::Addr(*SYSTEM_TX_CALLER))
            .to(AddrOrWallet::Addr(*L1_BLOCK))
            .nonce(word!("0x48"))
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
                00000000000000000000000000000000000000000000000000000000000007d0",
                )
                .unwrap()
                .into(),
            )
            .mint(word!("0x0"))
            .source_hash(
                Hash::from_str(
                    "0x20bae9fe252823414190884e97a5219704d96df8451ac61e52f8ebe11df4161d",
                )
                .unwrap(),
            )
            .build_kroma(),
        #[cfg(feature = "kroma")]
        // Kroma legacy tx
        MockTransaction::default()
            .transaction_type(0u64)
            .hash(
                Hash::from_str(
                    "0x6e9d05e31c45653dc8c188ce67a0038ce7f8707a44c2add4fe5ba6ce0caec1fa",
                )
                .unwrap(),
            )
            .transaction_idx(2u64)
            .from(AddrOrWallet::Addr(address!(
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            )))
            .to(AddrOrWallet::Addr(address!(
                "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
            )))
            .nonce(word!("0x0"))
            .value(word!("0xde0b6b3a7640000"))
            .gas(word!("0x5208"))
            .gas_price(word!("0x3b9c2b4a"))
            .input(Bytes::from(b""))
            .sig_data((
                1837u64,
                Word::from("0x70e69cab41c0933ab4bbdb43232c23271209770c561681f4118636777232bb3c"),
                Word::from("0x2d102204d2e8e80177cc9f02b88552e6a6a400b13e8d7b8585603c29b49e4fa8"),
            ))
            .build(),
        #[cfg(feature = "kroma")]
        // Kroma deploy tx
        MockTransaction::default()
            .hash(
                Hash::from_str(
                    "0x1b384a5effb97623025407c4dcc0e947e7ea4f52f0ed4bf1548db337a6501356",
                )
                .unwrap(),
            )
            .nonce(word!("0x0"))
            .from(AddrOrWallet::Addr(address!(
                "0xeefca179f40d3b8b3d941e6a13e48835a3af8241"
            )))
            .value(word!("0x0"))
            .gas(word!("0xf4240"))
            .gas_price(word!("0x1"))
            .input(
                hex::decode("6960606060606060606060600052610014610142f3")
                    .unwrap()
                    .into(),
            )
            .sig_data((
                2711,
                Word::from_str(
                    "0xabfa2ed41f429e227e7cf9f2e64b3935c1514f39011c43618bc1005d29a41f1d",
                )
                .unwrap(),
                Word::from_str(
                    "0x6d9c6ba0f8c435d79c2016488b52756cc5553b1140a1a11f8b2b4cc4b97cb406",
                )
                .unwrap(),
            ))
            .build(),
    ]
});

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
    pub nonce: Word,
    pub block_hash: Hash,
    pub block_number: U64,
    pub transaction_index: U64,
    pub from: AddrOrWallet,
    pub to: Option<AddrOrWallet>,
    pub value: Word,
    pub gas_price: Option<Word>,
    pub gas: Word,
    pub input: Bytes,
    pub v: Option<U64>,
    pub r: Option<Word>,
    pub s: Option<Word>,
    pub transaction_type: U64,
    pub access_list: AccessList,
    pub max_priority_fee_per_gas: Word,
    pub max_fee_per_gas: Word,
    pub chain_id: u64,
    /// Kroma deposit tx.
    #[cfg(feature = "kroma")]
    pub mint: Word,
    #[cfg(feature = "kroma")]
    pub source_hash: Hash,
}

impl Default for MockTransaction {
    fn default() -> Self {
        MockTransaction {
            hash: None,
            nonce: Word::zero(),
            block_hash: Hash::zero(),
            block_number: U64::zero(),
            transaction_index: U64::zero(),
            //from: AddrOrWallet::Addr(MOCK_ACCOUNTS[0]),
            from: AddrOrWallet::random(&mut OsRng),
            to: None,
            value: Word::zero(),
            gas_price: None,
            gas: Word::from(1_000_000u64),
            input: Bytes::default(),
            v: None,
            r: None,
            s: None,
            transaction_type: U64::zero(),
            access_list: AccessList::default(),
            max_priority_fee_per_gas: Word::zero(),
            max_fee_per_gas: Word::zero(),
            chain_id: MOCK_CHAIN_ID,
            #[cfg(feature = "kroma")]
            mint: Word::zero(),
            #[cfg(feature = "kroma")]
            source_hash: Hash::zero(),
        }
    }
}

impl From<MockTransaction> for Transaction {
    fn from(mock: MockTransaction) -> Self {
        Transaction {
            hash: mock.hash.unwrap_or_default(),
            nonce: mock.nonce,
            block_hash: Some(mock.block_hash),
            block_number: Some(mock.block_number),
            transaction_index: Some(mock.transaction_index),
            from: mock.from.address(),
            to: mock.to.map(|addr| addr.address()),
            value: mock.value,
            gas_price: mock.gas_price,
            gas: mock.gas,
            input: mock.input,
            v: mock.v.unwrap_or_default(),
            r: mock.r.unwrap_or_default(),
            s: mock.s.unwrap_or_default(),
            #[cfg(feature = "kroma")]
            source_hash: Some(mock.source_hash),
            #[cfg(feature = "kroma")]
            mint: Some(mock.mint),
            transaction_type: Some(mock.transaction_type),
            access_list: Some(mock.access_list),
            max_priority_fee_per_gas: Some(mock.max_priority_fee_per_gas),
            max_fee_per_gas: Some(mock.max_fee_per_gas),
            chain_id: Some(mock.chain_id.into()),
            other: OtherFields::default(),
        }
    }
}

impl From<MockTransaction> for GethTransaction {
    fn from(mock: MockTransaction) -> Self {
        GethTransaction::from(&Transaction::from(mock))
    }
}

impl MockTransaction {
    /// Tx Hash computed based on the fields of the Tx by
    /// default unless `Some(hash)` is specified on build process.
    pub fn hash(&mut self, hash: Hash) -> &mut Self {
        self.hash = Some(hash);
        self
    }

    /// Set nonce field for the MockTransaction.
    pub fn nonce(&mut self, nonce: Word) -> &mut Self {
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
        self.gas_price = Some(gas_price);
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
        self.transaction_type = U64::from(transaction_type);
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
        if self.transaction_type == U64::from(2) {
            return self.build_1559();
        }
        // TODO: handle eip2930 type later when add eip2930 tests.

        let tx = TransactionRequest::new()
            .from(self.from.address())
            .nonce(self.nonce)
            .value(self.value)
            .data(self.input.clone())
            .gas(self.gas)
            .chain_id(self.chain_id);

        let tx = if let Some(gas_price) = self.gas_price {
            tx.gas_price(gas_price)
        } else {
            tx
        };
        let tx = if let Some(to_addr) = self.to.clone() {
            tx.to(to_addr.address())
        } else {
            tx
        };

        match (self.v, self.r, self.s) {
            (None, None, None) => {
                // Compute sig params and set them in case we have a wallet as `from` attr.
                if self.from.is_wallet() && self.hash.is_none() {
                    let sig = self
                        .from
                        .as_wallet()
                        .with_chain_id(self.chain_id)
                        .sign_transaction_sync(&tx.into()) // sign for legacy tx type in ethers-rs.
                        .expect("sign mock tx");
                    // Set sig parameters
                    self.sig_data((sig.v, sig.r, sig.s));
                }
            }
            _ => panic!("Either all or none of the SigData params have to be set"),
        }

        // Compute tx hash in case is not already set
        if self.hash.is_none() {
            let tmp_tx = Transaction::from(self.to_owned());
            // FIXME: Note that tmp_tx does not have sigs if self.from.is_wallet() = false.
            //  This means tmp_tx.hash() is not correct.

            self.hash(tmp_tx.hash());
        }

        self.to_owned()
    }

    /// build 1559 type tx
    pub fn build_1559(&mut self) -> Self {
        let tx = Eip1559TransactionRequest::new()
            .from(self.from.address())
            .nonce(self.nonce)
            .value(self.value)
            .data(self.input.clone())
            .gas(self.gas)
            .chain_id(self.chain_id)
            .max_priority_fee_per_gas(self.max_priority_fee_per_gas)
            .max_fee_per_gas(self.max_fee_per_gas)
            .access_list(self.access_list.clone());

        let tx = if let Some(to_addr) = self.to.clone() {
            tx.to(to_addr.address())
        } else {
            tx
        };

        match (self.v, self.r, self.s) {
            (None, None, None) => {
                // Compute sig params and set them in case we have a wallet as `from` attr.
                if self.from.is_wallet() && self.hash.is_none() {
                    let mut sig = self
                        .from
                        .as_wallet()
                        .with_chain_id(self.chain_id)
                        .sign_transaction_sync(&tx.into())
                        .expect("sign mock 1559 tx");

                    // helper `sign_transaction_sync` in ethers-rs lib does not handle correctly
                    // about v for non legacy tx, here correct it for 1559 type.
                    sig.v = Self::normalize_v(sig.v, self.chain_id); // convert v to [0, 1]

                    self.sig_data((sig.v, sig.r, sig.s));
                } else {
                    #[cfg(feature = "scroll")]
                    panic!("1559 type tx must have signature data, otherwise will be treated as L1Msg type in trace.go of l2geth");
                }
            }
            _ => panic!("Either all or none of the SigData params have to be set"),
        }

        // Compute tx hash in case is not already set
        if self.hash.is_none() {
            let tmp_tx = Transaction::from(self.to_owned());
            // FIXME: Note that tmp_tx does not have sigs if self.from.is_wallet() = false.
            //  This means tmp_tx.hash() is not correct.
            self.hash(tmp_tx.hash());
        }

        self.to_owned()
    }

    // helper `sign_transaction_sync` in ethers-rs lib compute V using legacy tx pattern(V =
    // recover_id + 2 * chain_id + 35), this method converts above V value to origin recover_id.
    pub(crate) fn normalize_v(v: u64, chain_id: u64) -> u64 {
        if v > 1 {
            v - chain_id * 2 - 35
        } else {
            v
        }
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
