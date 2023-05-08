//! Tx circuit benchmarks

#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use bus_mapping::circuit_input_builder::{BuilderClient, CircuitsParams};
    use env_logger::Env;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
    use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::ParamsProver,
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use log;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use zkevm_circuits::tx_circuit::TxCircuit;
    use zkevm_circuits::util::SubCircuit;
    use zkevm_circuits::witness::block_convert;

    // use crate::bench_params::DEGREE;
    use bus_mapping::rpc::GethClient;
    use ethers::providers::Http;
    use url::Url;

    fn get_client() -> GethClient<Http> {
        let geth_url = "http://localhost:9545";
        let transport = Http::new(Url::parse(geth_url).expect("invalid url"));
        GethClient::new(transport)
    }

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[tokio::test]
    async fn bench_tx_circuit_prover() {
        env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

        // Approximate value, adjust with changes on the TxCircuit.
        let degree = std::env::var("DEGREE")
            .expect("DEGREE Not Set")
            .parse::<usize>()
            .expect("DEGREE should be int");
        // const ROWS_PER_TX: usize = 175_000;
        // const MAX_TXS: usize = 2_usize.pow(degree as u32) / ROWS_PER_TX;
        // const MAX_CALLDATA: usize = 1024;

        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let block_num = 16140307_u64;
        log::info!("test super circuit, block number: {}", block_num);
        let cli = get_client();
        // target k = 19
        let params = CircuitsParams {
            max_rws: 4_000_000,
            max_copy_rows: 4_000_000,
            max_txs: 500,
            max_calldata: 2_000_000,
            max_inner_blocks: 64,
            max_bytecode: 3_000_000,
            keccak_padding: None,
        };
        let cli = BuilderClient::new(cli, params).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num).await.unwrap();

        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            return;
        }
        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        // let chain_id: u64 = mock::MOCK_CHAIN_ID.low_u64();
        // let txs = vec![mock::CORRECT_MOCK_TXS[0].clone().into()];
        // let circuit = TxCircuit::<Fr>::new(MAX_TXS, MAX_CALLDATA, chain_id, txs);
        let circuit = TxCircuit::new_from_block(&block);

        // Bench setup generation
        let setup_message = format!("Setup generation with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree as u32, &mut rng);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        // Initialize the proving key
        let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("Tx Circuit Proof generation with degree = {}", degree);
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            ChaCha20Rng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            TxCircuit<Fr>,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&[&[]]],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        // Bench verification time
        let start3 = start_timer!(|| "Tx Circuit Proof verification");
        let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&general_params);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[&[&[]]],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
