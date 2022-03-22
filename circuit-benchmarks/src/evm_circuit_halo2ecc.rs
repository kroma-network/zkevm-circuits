use crate::bench_params::DEGREE;
use crate::evm_circuit::TestCircuit;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Blake2bWrite;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2_snark_aggregator::circuits::five::integer_circuit::{
    FiveColumnIntegerCircuit, COMMON_RANGE_BITS,
};
use halo2_snark_aggregator::circuits::native_ecc_circuit::NativeEccCircuit;
use halo2_snark_aggregator::gates::base_gate::RegionAux;
use halo2_snark_aggregator::gates::five::base_gate::{
    FiveColumnBaseGate, FiveColumnBaseGateConfig,
};
use halo2_snark_aggregator::gates::five::range_gate::FiveColumnRangeGate;
use halo2_snark_aggregator::gates::range_gate::RangeGateConfig;
use halo2_snark_aggregator::verify::halo2::verify::query::IVerifierParams;
use halo2_snark_aggregator::verify::halo2::verify::*;
use pairing::bn256::{Bn256, Fq, Fr, G1Affine};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::env::var;
use std::marker::PhantomData;

enum TestCase {
    Normal,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Normal
    }
}

#[derive(Clone)]
struct TestEvmCircuitEccCircuitConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestEvmCircuitEccCircuit<C: CurveAffine> {
    test_case: TestCase,
    _phantom_w: PhantomData<C>,
}

impl TestEvmCircuitEccCircuit<G1Affine> {
    fn setup_test(
        &self,
        ecc_gate: &NativeEccCircuit<'_, G1Affine>,
        base_gate: &FiveColumnBaseGate<Fr>,
        r: &mut RegionAux<'_, '_, Fr>,
    ) -> Result<(), Error> {
        let degree: u32 = var("DEGREE")
            .expect("No DEGREE env var was provided")
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        let circuit = TestCircuit::<Fr>::default();
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let general_params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(degree);

        let vk = keygen_vk(&general_params, &circuit).unwrap();
        let pk = keygen_pk(&general_params, vk, &circuit).unwrap();

        // Prove
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof(
            &general_params,
            &pk,
            &[circuit],
            &[&[]],
            rng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();

        let verifier_params: ParamsVerifier<Bn256> = general_params.verifier(DEGREE * 2).unwrap();
        let mut verifier_transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(verifier_params.k);
        let params_verifier: ParamsVerifier<Bn256> = params.verifier(DEGREE * 2).unwrap();

        let param = VerifierParams::from_transcript(
            base_gate,
            ecc_gate,
            r,
            Fr::zero(),
            &[&[]],
            pk.get_vk(),
            &params_verifier,
            &mut verifier_transcript,
        )
        .unwrap();
        let _ = param.queries(base_gate, r).unwrap();

        Ok(())
    }
}

impl Circuit<Fr> for TestEvmCircuitEccCircuit<G1Affine> {
    type Config = TestEvmCircuitEccCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::<Fr>::configure(meta);
        let range_gate_config = FiveColumnRangeGate::<'_, Fq, Fr, COMMON_RANGE_BITS>::configure(
            meta,
            &base_gate_config,
        );
        TestEvmCircuitEccCircuitConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.base_gate_config);
        let range_gate = FiveColumnRangeGate::<'_, Fq, Fr, COMMON_RANGE_BITS>::new(
            config.range_gate_config,
            &base_gate,
        );
        let integer_gate = FiveColumnIntegerCircuit::new(&range_gate);
        let ecc_gate = NativeEccCircuit::new(&integer_gate);

        range_gate
            .init_table(&mut layouter, &integer_gate.helper.integer_modulus)
            .unwrap();

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut aux = RegionAux::new(&mut region, &mut base_offset);
                let r = &mut aux;
                let round = 1;
                for _ in 0..round {
                    match self.test_case {
                        TestCase::Normal => self.setup_test(&ecc_gate, &base_gate, r),
                    }?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}
#[cfg(test)]
mod evm_halo2_snark_aggregator_circ_benches {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use pairing::bn256::G1Affine;
    use std::marker::PhantomData;

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_evm_halo2_snark_aggregator_circuit_prover() {
        const K: u32 = 20 as u32;
        let circuit = TestEvmCircuitEccCircuit::<G1Affine> {
            test_case: TestCase::Normal,
            _phantom_w: PhantomData,
        };
        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
