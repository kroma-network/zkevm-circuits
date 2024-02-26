use crate::{get_client, GenDataOutput};
use bus_mapping::{
    circuit_input_builder::{BuilderClient, CircuitInputBuilder, CircuitsParams},
    mock::BlockData,
};
use eth_types::geth_types::GethData;
use halo2_proofs::{
    arithmetic::Field,
    bn254::{
        Blake2bWrite as TachyonBlake2bWrite, ProvingKey as TachyonProvingKey,
        SHPlonkProver as TachyonSHPlonkProver, TachyonProver,
    },
    consts::{TranscriptType, SEED},
    dev::{CellValue, MockProver},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, tachyon::create_proof as create_tachyon_proof,
        verify_proof, Circuit, ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use lazy_static::lazy_static;
use mock::TestContext;
use rand_chacha::rand_core::SeedableRng;
use rand_core::RngCore;
use rand_xorshift::XorShiftRng;
use std::{collections::HashMap, marker::PhantomData, sync::Mutex};
use tokio::sync::Mutex as TokioMutex;
use zkevm_circuits::{
    bytecode_circuit::circuit::BytecodeCircuit,
    copy_circuit::CopyCircuit,
    evm_circuit::EvmCircuit,
    exp_circuit::ExpCircuit,
    keccak_circuit::KeccakCircuit,
    state_circuit::StateCircuit,
    super_circuit::SuperCircuit,
    tx_circuit::TxCircuit,
    util::SubCircuit,
    witness::{block_convert, Block},
};

/// TEST_MOCK_RANDOMNESS
const TEST_MOCK_RANDOMNESS: u64 = 0x100;

/// MAX_RWS
#[cfg(not(feature = "kroma"))]
const MAX_RWS: usize = 5888;
#[cfg(feature = "kroma")]
const MAX_RWS: usize = 16384;
/// MAX_TXS
#[cfg(not(feature = "kroma"))]
const MAX_TXS: usize = 4;
#[cfg(feature = "kroma")]
const MAX_TXS: usize = 5;
/// MAX_CALLDATA
#[cfg(not(feature = "kroma"))]
const MAX_CALLDATA: usize = 512;
#[cfg(feature = "kroma")]
const MAX_CALLDATA: usize = 4000;
/// MAX_INNER_BLOCKS
pub const MAX_INNER_BLOCKS: usize = 64;
/// MAX_BYTECODE
const MAX_BYTECODE: usize = 10000;
/// MAX_COPY_ROWS
#[cfg(not(feature = "kroma"))]
const MAX_COPY_ROWS: usize = 5888;
#[cfg(feature = "kroma")]
const MAX_COPY_ROWS: usize = 16384;
/// MAX_EVM_ROWS
const MAX_EVM_ROWS: usize = 10000;
/// MAX_EXP_STEPS
const MAX_EXP_STEPS: usize = 1000;
const MAX_KECCAK_ROWS: usize = 20000;

const CIRCUITS_PARAMS: CircuitsParams = CircuitsParams {
    max_rws: MAX_RWS,
    max_txs: MAX_TXS,
    max_calldata: MAX_CALLDATA,
    max_inner_blocks: 64,
    max_bytecode: MAX_BYTECODE,
    max_copy_rows: MAX_COPY_ROWS,
    max_evm_rows: MAX_EVM_ROWS,
    max_exp_steps: MAX_EXP_STEPS,
    max_keccak_rows: MAX_KECCAK_ROWS,
};

const EVM_CIRCUIT_DEGREE: u32 = 18;
const STATE_CIRCUIT_DEGREE: u32 = 17;
const TX_CIRCUIT_DEGREE: u32 = 20;
const BYTECODE_CIRCUIT_DEGREE: u32 = 16;
const COPY_CIRCUIT_DEGREE: u32 = 16;
const KECCAK_CIRCUIT_DEGREE: u32 = 19;
const SUPER_CIRCUIT_DEGREE: u32 = 20;
const EXP_CIRCUIT_DEGREE: u32 = 16;

lazy_static! {
    /// Data generation.
    static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
    static ref RNG: XorShiftRng = XorShiftRng::from_seed(SEED);
}

lazy_static! {
    static ref GEN_PARAMS: Mutex<HashMap<u32, ParamsKZG<Bn256>>> = Mutex::new(HashMap::new());
}

lazy_static! {
    /// Integration test for EVM circuit
    pub static ref EVM_CIRCUIT_TEST: TokioMutex<IntegrationTest<EvmCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("EVM", EVM_CIRCUIT_DEGREE));

    /// Integration test for State circuit
    pub static ref STATE_CIRCUIT_TEST: TokioMutex<IntegrationTest<StateCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("State", STATE_CIRCUIT_DEGREE));

    /// Integration test for State circuit
    pub static ref TX_CIRCUIT_TEST: TokioMutex<IntegrationTest<TxCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Tx", TX_CIRCUIT_DEGREE));

    /// Integration test for Bytecode circuit
    pub static ref BYTECODE_CIRCUIT_TEST: TokioMutex<IntegrationTest<BytecodeCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Bytecode", BYTECODE_CIRCUIT_DEGREE));

    /// Integration test for Copy circuit
    pub static ref COPY_CIRCUIT_TEST: TokioMutex<IntegrationTest<CopyCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Copy", COPY_CIRCUIT_DEGREE));

    /// Integration test for Keccak circuit
    pub static ref KECCAK_CIRCUIT_TEST: TokioMutex<IntegrationTest<KeccakCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Keccak", KECCAK_CIRCUIT_DEGREE));

    /// Integration test for Copy circuit
    pub static ref SUPER_CIRCUIT_TEST: TokioMutex<IntegrationTest<SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>>> =
    TokioMutex::new(IntegrationTest::new("Super", SUPER_CIRCUIT_DEGREE));

     /// Integration test for Exp circuit
     pub static ref EXP_CIRCUIT_TEST: TokioMutex<IntegrationTest<ExpCircuit::<Fr>>> =
     TokioMutex::new(IntegrationTest::new("Exp", EXP_CIRCUIT_DEGREE));
}

/// Generic implementation for integration tests
pub struct IntegrationTest<C: SubCircuit<Fr> + Circuit<Fr>> {
    name: &'static str,
    degree: u32,
    key: Option<ProvingKey<G1Affine>>,
    fixed: Option<Vec<Vec<CellValue<Fr>>>>,
    _marker: PhantomData<C>,
}

impl<C: SubCircuit<Fr> + Circuit<Fr>> IntegrationTest<C> {
    fn new(name: &'static str, degree: u32) -> Self {
        Self {
            name,
            degree,
            key: None,
            fixed: None,
            _marker: PhantomData,
        }
    }

    fn get_key(&mut self) -> ProvingKey<G1Affine> {
        match self.key.clone() {
            Some(key) => key,
            None => {
                let block = new_empty_block();
                let circuit = C::new_from_block(&block);
                let general_params = get_general_params(self.degree);

                let verifying_key =
                    keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
                let key = keygen_pk(&general_params, verifying_key, &circuit)
                    .expect("keygen_pk should not fail");
                self.key = Some(key.clone());
                key
            }
        }
    }

    fn test_actual(&self, circuit: C, instance: Vec<Vec<Fr>>, proving_key: ProvingKey<G1Affine>) {
        fn test_gen_proof<C: Circuit<Fr>, R: RngCore>(
            rng: R,
            circuit: C,
            general_params: &ParamsKZG<Bn256>,
            proving_key: &ProvingKey<G1Affine>,
            instances: &[&[Fr]],
        ) -> Vec<u8> {
            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                R,
                Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
                C,
            >(
                general_params,
                proving_key,
                &[circuit],
                &[instances],
                rng,
                &mut transcript,
            )
            .expect("proof generation should not fail");

            transcript.finalize()
        }

        fn test_gen_tachyon_proof<C: Circuit<Fr>>(
            k: u32,
            circuit: C,
            pk: &ProvingKey<G1Affine>,
            instances: &[&[Fr]],
        ) -> Vec<u8> {
            let rng = halo2_proofs::xor_shift_rng::XORShiftRng::from_seed(SEED);

            let s = Fr::random(rng.clone());
            let mut prover = TachyonSHPlonkProver::<KZGCommitmentScheme<Bn256>>::new(
                TranscriptType::Blake2b as u8,
                k,
                &s,
            );

            let mut pk_bytes: Vec<u8> = vec![];
            pk.write(&mut pk_bytes, halo2_proofs::SerdeFormat::RawBytesUnchecked)
                .unwrap();
            let mut tachyon_pk = TachyonProvingKey::from(pk_bytes.as_slice());

            let mut transcript = TachyonBlake2bWrite::init(vec![]);

            create_tachyon_proof::<_, _, _, _, _>(
                &mut prover,
                &mut tachyon_pk,
                &[circuit],
                &[instances],
                rng,
                &mut transcript,
            )
            .expect("proof generation should not fail");

            let mut proof = transcript.finalize();
            let proof_last = prover.get_proof();
            proof.extend_from_slice(&proof_last);
            proof
        }

        fn test_verify(
            general_params: &ParamsKZG<Bn256>,
            verifier_params: &ParamsKZG<Bn256>,
            verifying_key: &VerifyingKey<G1Affine>,
            proof: &[u8],
            instances: &[&[Fr]],
        ) {
            let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof);
            let strategy = SingleStrategy::new(general_params);

            verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
                SingleStrategy<'_, Bn256>,
            >(
                verifier_params,
                verifying_key,
                strategy,
                &[instances],
                &mut verifier_transcript,
            )
            .expect("failed to verify circuit");
        }

        let mut general_params: Option<ParamsKZG<Bn256>> = None;

        // change instace to slice
        let instance: Vec<&[Fr]> = instance.iter().map(|v| v.as_slice()).collect();

        #[cfg(feature = "tachyon")]
        let proof = test_gen_tachyon_proof(self.degree, circuit, &proving_key, &instance);
        #[cfg(not(feature = "tachyon"))]
        let proof = {
            general_params = Some(get_general_params(self.degree));
            test_gen_proof(
                RNG.clone(),
                circuit,
                &general_params.as_ref().unwrap(),
                &proving_key,
                &instance,
            )
        };
        log::debug!("proof: {:?}", proof);

        #[cfg(feature = "tachyon")]
        {
            general_params = Some(get_general_params(self.degree));
        }
        let verifier_params: ParamsVerifierKZG<Bn256> =
            general_params.as_ref().unwrap().verifier_params().clone();

        let verifying_key = proving_key.get_vk();
        test_verify(
            &general_params.unwrap(),
            &verifier_params,
            verifying_key,
            &proof,
            &instance,
        );
    }

    fn test_mock(&mut self, circuit: &C, instance: Vec<Vec<Fr>>) {
        let mock_prover = MockProver::<Fr>::run(self.degree, circuit, instance).unwrap();

        self.test_variadic(&mock_prover);

        mock_prover
            .verify_par()
            .expect("mock prover verification failed");
    }

    fn test_variadic(&mut self, mock_prover: &MockProver<Fr>) {
        let fixed = mock_prover.fixed();

        match self.fixed.clone() {
            Some(prev_fixed) => {
                assert!(
                    fixed.eq(&prev_fixed),
                    "circuit fixed columns are not constant for different witnesses"
                );
            }
            None => {
                self.fixed = Some(fixed.clone());
            }
        };

        // TODO: check mock_prover.permutation(), currently the returning type
        // is private so cannot store.
    }

    /// Run integration test at a block identified by a tag.
    pub async fn test_at_block_tag(&mut self, block_tag: &str, actual: bool) {
        let block_num = *GEN_DATA.blocks.get(block_tag).unwrap();
        let (builder, _) = gen_inputs(block_num).await;

        log::info!(
            "test {} circuit, block: #{} - {}",
            self.name,
            block_num,
            block_tag
        );
        let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
        block.randomness = Fr::from(TEST_MOCK_RANDOMNESS);
        let circuit = C::new_from_block(&block);
        let instance = circuit.instance();

        if actual {
            let key = self.get_key();
            self.test_actual(circuit, instance, key);
        } else {
            self.test_mock(&circuit, instance);
        }
    }
}

fn new_empty_block() -> Block<Fr> {
    let block: GethData = TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
        .unwrap()
        .into();
    let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), CIRCUITS_PARAMS)
        .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    block_convert(&builder.block, &builder.code_db).unwrap()
}

fn get_general_params(degree: u32) -> ParamsKZG<Bn256> {
    let mut map = GEN_PARAMS.lock().unwrap();
    match map.get(&degree) {
        Some(params) => params.clone(),
        None => {
            let params = ParamsKZG::<Bn256>::setup(degree, RNG.clone());
            map.insert(degree, params.clone());
            params
        }
    }
}

/// returns gen_inputs for a block number
async fn gen_inputs(
    block_num: u64,
) -> (
    CircuitInputBuilder,
    eth_types::Block<eth_types::Transaction>,
) {
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();

    cli.gen_inputs(block_num).await.unwrap()
}
