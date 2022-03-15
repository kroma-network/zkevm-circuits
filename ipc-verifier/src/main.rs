use halo2_proofs::{
    plonk::{keygen_vk, verify_proof, SingleVerifier, VerifyingKey},
    poly::commitment::{Params, ParamsVerifier},
    transcript::{Blake2bRead, Challenge255},
};
use pairing::bn256::{Bn256, Fr, G1Affine};
use std::fs;
use std::io::{Cursor, Error as IOError, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use zkevm_circuits::state_circuit::StateCircuit;

use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};
use zkevm_circuits::evm_circuit::{witness::Block, EvmCircuit};

const SOCKET_PATH: &'static str = "/tmp/verifier.sock";
// TODO: what should this be?
const DEGREE: u32 = 1;

fn main() {
    let socket = Path::new(SOCKET_PATH);

    // Delete old socket if present
    if socket.exists() {
        fs::remove_file(&socket).expect("should be able to clear out old socket file");
    }

    // Start a server on the unix socket
    let listener = UnixListener::bind(&socket).expect("should be able to bind to unix socket");

    let (mut socket, _addr) = listener
        .accept()
        .expect("should be able to accept a connection");

    // Set up params
    // TODO: this should probably come from a transcript file later on
    let general_params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(DEGREE);
    let evm_circuit = TestCircuit::<Fr>::default();
    // TODO: where do i get the config?
    let state_circuit = StateCircuit::<Fr, true, 49152, 16384, 2000, 16384, 1300, 16384>::default();

    let evm_vk = keygen_vk(&general_params, &evm_circuit).unwrap();

    let state_vk = keygen_vk(&general_params, &state_circuit).unwrap();

    let verifier_params: ParamsVerifier<Bn256> =
        general_params.verifier((DEGREE * 2) as usize).unwrap();

    loop {
        // Read msg length
        let mut buf = [0u8; 4];
        socket
            .read_exact(&mut buf)
            .expect("should be able to read from socket");

        let msg_length = u32::from_le_bytes(buf);

        let mut buf = vec![0u8; msg_length as usize];
        socket
            .read_exact(&mut buf)
            .expect("should be able to read proof message");

        let mut reader = Cursor::new(buf);
        let (evm_proof, state_proof) =
            recover_transcripts(&mut reader).expect("should be able to recover proofs");

        let verified = verify_proofs(evm_proof, state_proof, &verifier_params, &evm_vk, &state_vk);

        socket
            .write(&vec![verified as u8])
            .expect("should be able to write to the sequencer");
    }
}

fn recover_transcripts<R: Read>(reader: &mut R) -> Result<(Vec<u8>, Vec<u8>), IOError> {
    // We don't look at the first 8 bytes as they just contain the ID.
    let mut id_buf = [0u8; 8];
    reader.read_exact(&mut id_buf)?;
    drop(id_buf);

    let evm_proof = extract_proof(reader)?;
    let state_proof = extract_proof(reader)?;

    Ok((evm_proof, state_proof))
}

fn extract_proof<R: Read>(reader: &mut R) -> Result<Vec<u8>, IOError> {
    let mut proof_len_buf = [0u8; 4];
    reader.read_exact(&mut proof_len_buf)?;

    let proof_len = u32::from_le_bytes(proof_len_buf);
    let mut proof_buf = vec![0u8; proof_len as usize];
    reader.read_exact(&mut proof_buf)?;
    Ok(proof_buf.to_vec())
}

fn verify_proofs(
    evm_proof: Vec<u8>,
    state_proof: Vec<u8>,
    verifier_params: &ParamsVerifier<Bn256>,
    evm_vk: &VerifyingKey<G1Affine>,
    state_vk: &VerifyingKey<G1Affine>,
) -> bool {
    // State
    let mut verifier_transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&state_proof[..]);
    let strategy = SingleVerifier::new(&verifier_params);

    verify_proof(
        &verifier_params,
        state_vk,
        strategy,
        &[&[]],
        &mut verifier_transcript,
    )
    .is_ok()
}

/////////////////////////////////////////////////////////////////////////
// I'm implementing this here so that I can actually use EvmCircuit    //
// This should be removed once Circuit is actually implemented for it. //
/////////////////////////////////////////////////////////////////////////

#[derive(Debug, Default)]
pub struct TestCircuit<F> {
    block: Block<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = EvmCircuit<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = [(); 4].map(|_| meta.advice_column());
        let rw_table = [(); 10].map(|_| meta.advice_column());
        let bytecode_table = [(); 4].map(|_| meta.advice_column());
        let block_table = [(); 3].map(|_| meta.advice_column());
        // Use constant expression to mock constant instance column for a more
        // reasonable benchmark.
        let power_of_randomness = [(); 31].map(|_| Expression::Constant(F::one()));

        EvmCircuit::configure(
            meta,
            power_of_randomness,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign_block(&mut layouter, &self.block)
    }
}
