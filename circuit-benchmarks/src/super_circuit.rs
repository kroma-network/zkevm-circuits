//! SuperCircuit circuit benchmarks

#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use eth_types::geth_types::GethData;
    use eth_types::{address, bytecode, Word};
    use ethers_signers::LocalWallet;
    use ethers_signers::Signer;
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
    #[cfg(feature = "kanvas")]
    use mock::test_ctx::helpers::{account_n_l1_block_np1_system_tx_caller, system_deposit_tx};
    use mock::{tx_idx, SimpleTestContext, MOCK_CHAIN_ID};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::collections::HashMap;
    use std::env::var;
    use zkevm_circuits::super_circuit::SuperCircuit;

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_super_circuit_prover() {
        let degree: u32 = var("DEGREE")
            .expect("No DEGREE env var was provided")
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        let mut rng = ChaChaRng::seed_from_u64(2);

        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let bytecode = bytecode! {
            STOP
        };

        let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

        let addr_a = wallet_a.address();
        let addr_b = address!("0x000000000000000000000000000000000000BBBB");

        let mut wallets = HashMap::new();
        wallets.insert(wallet_a.address(), wallet_a);

        let mut block: GethData = SimpleTestContext::new(
            None,
            #[allow(unused_mut)]
            |mut accs| {
                accs[0]
                    .address(addr_b)
                    .balance(Word::from(1u64 << 20))
                    .code(bytecode);
                accs[1].address(addr_a).balance(Word::from(1u64 << 20));
                #[cfg(feature = "kanvas")]
                account_n_l1_block_np1_system_tx_caller(accs.as_mut_slice(), 2);
            },
            |mut txs, accs| {
                #[cfg(feature = "kanvas")]
                system_deposit_tx(txs[0]);
                txs[tx_idx!(0)]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(Word::from(1_000_000u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        block.sign(&wallets);

        let (_, circuit, instance, _) =
            SuperCircuit::<_, 1, 32, 64, 512, 512>::build(block).unwrap();
        let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();

        // Bench setup generation
        let setup_message = format!("Setup generation with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        // Initialize the proving key
        let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("SuperCircuit Proof generation with degree = {}", degree);
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            ChaChaRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            SuperCircuit<Fr, 1, 32, 64, 512, 512>,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&instance_refs],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        // Bench verification time
        let start3 = start_timer!(|| "SuperCircuit Proof verification");
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
            &[&instance_refs],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
