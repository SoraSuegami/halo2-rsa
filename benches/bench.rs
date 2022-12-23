use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_dynamic_sha256::{Sha256Chip, Sha256Config, Table16Chip};
use halo2_rsa::{
    big_integer::{BigIntConfig, BigIntInstructions, UnassignedInteger},
    RSAChip, RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature, RSASignatureVerifier,
};
use halo2wrong::{
    curves::FieldExt,
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
            ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
        },
        poly::{
            commitment::CommitmentScheme,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
};
use maingate::{
    decompose_big, MainGate, MainGateInstructions, RangeChip, RangeInstructions, RegionCtx,
};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use std::marker::PhantomData;

use halo2wrong::curves::bn256::{Bn256, Fr, G1Affine};
use halo2wrong::halo2::dev::MockProver;
use rand::{thread_rng, Rng};
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
struct Pkcs1v15BenchConfig {
    rsa_config: RSAConfig,
    sha256_config: Option<Sha256Config>,
}
macro_rules! impl_pkcs1v15_bench_circuit {
    ($circuit_name:ident, $setup_fn_name:ident, $prove_fn_name:ident, $k:expr, $n_bits:expr, $msg_bytes:expr, $sha2_chip_enabled:expr) => {
        struct $circuit_name<F: FieldExt> {
            signature: RSASignature<F>,
            public_key: RSAPublicKey<F>,
            msg: Vec<u8>,
            _f: PhantomData<F>,
        }

        impl<F: FieldExt> Default for $circuit_name<F> {
            fn default() -> Self {
                let num_limbs = Self::BITS_LEN / RSAChip::<F>::LIMB_WIDTH;
                let signature = RSASignature::without_witness(num_limbs);
                let public_key =
                    RSAPublicKey::without_witness(num_limbs, BigUint::from(Self::DEFAULT_E));
                let msg = if $sha2_chip_enabled {
                    vec![0; $msg_bytes]
                } else {
                    vec![0; 32]
                };
                Self {
                    signature,
                    public_key,
                    msg,
                    _f: PhantomData,
                }
            }
        }

        impl<F: FieldExt> $circuit_name<F> {
            const BITS_LEN: usize = $n_bits;
            const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH;
            const EXP_LIMB_BITS: usize = 5;
            const DEFAULT_E: u128 = 65537;
            fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
                RSAChip::new(config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
            }
            fn sha256_chip(&self, config: Sha256Config) -> Sha256Chip<F> {
                Sha256Chip::new(config)
            }
        }

        impl<F: FieldExt> Circuit<F> for $circuit_name<F> {
            type Config = Pkcs1v15BenchConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                // 1. Configure `MainGate`.
                let main_gate_config = MainGate::<F>::configure(meta);
                // 2. Compute bit length parameters by calling `RSAChip::<F>::compute_range_lens` function.
                let (composition_bit_lens, overflow_bit_lens) =
                    RSAChip::<F>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH);
                // 3. Configure `RangeChip`.
                let range_config = RangeChip::<F>::configure(
                    meta,
                    &main_gate_config,
                    composition_bit_lens,
                    overflow_bit_lens,
                );
                // 4. Configure `BigIntConfig`.
                let bigint_config =
                    BigIntConfig::new(range_config.clone(), main_gate_config.clone());
                // 5. Configure `RSAConfig`.
                let rsa_config = RSAConfig::new(bigint_config);
                // 6. Configure `Sha256Config`.
                let sha256_config = if $sha2_chip_enabled {
                    let table16_congig = Table16Chip::configure(meta);
                    Some(Sha256Config::new(
                        main_gate_config,
                        range_config,
                        table16_congig,
                        $msg_bytes + 64,
                    ))
                } else {
                    None
                };
                Self::Config {
                    rsa_config,
                    sha256_config,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
            ) -> Result<(), Error> {
                let rsa_chip = self.rsa_chip(config.rsa_config);
                let bigint_chip = rsa_chip.bigint_chip();
                let main_gate = rsa_chip.main_gate();
                // Create lookup tables for range check in `range_chip`.
                let range_chip = bigint_chip.range_chip();
                range_chip.load_table(&mut layouter)?;

                // 1. Assign a public key and signature.
                let (public_key, signature) = layouter.assign_region(
                    || "rsa signature with hash test using 2048 bits public keys",
                    |region| {
                        let offset = 0;
                        let ctx = &mut RegionCtx::new(region, offset);
                        let sign = rsa_chip.assign_signature(ctx, self.signature.clone())?;
                        let public_key =
                            rsa_chip.assign_public_key(ctx, self.public_key.clone())?;
                        Ok((public_key, sign))
                    },
                )?;
                if $sha2_chip_enabled {
                    let sha256_chip = self.sha256_chip(config.sha256_config.unwrap());
                    // 2. Create a RSA signature verifier from `RSAChip` and `Sha256BitChip`
                    let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
                    // 3. Receives the verification result and the resulting hash of `self.msg` from `RSASignatureVerifier`.
                    let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                        layouter.namespace(|| "verify pkcs1v15 signature"),
                        &public_key,
                        &self.msg,
                        &signature,
                    )?;

                    //4. Expose the resulting hash as public input.
                    for (i, val) in hashed_msg.into_iter().enumerate() {
                        main_gate.expose_public(
                            layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                            val,
                            i,
                        )?;
                    }
                    // 5. The verification result must be one.
                    layouter.assign_region(
                        || "assert is_valid==1 (sha2 enabled)",
                        |region| {
                            let offset = 0;
                            let ctx = &mut RegionCtx::new(region, offset);
                            main_gate.assert_one(ctx, &is_valid)?;
                            Ok(())
                        },
                    )?;
                } else {
                    let is_valid = layouter.assign_region(
                        || "get is_valid (sha2 disabled)",
                        |region| {
                            let offset = 0;
                            let ctx = &mut RegionCtx::new(region, offset);
                            let hashed_msg_big = BigUint::from_bytes_le(&self.msg);
                            let hashed_msg_limbs = decompose_big::<F>(
                                hashed_msg_big.clone(),
                                4,
                                RSAChip::<F>::LIMB_WIDTH,
                            );
                            let hashed_msg_unassigned = UnassignedInteger::from(hashed_msg_limbs);
                            let hashed_msg_assigned =
                                bigint_chip.assign_integer(ctx, hashed_msg_unassigned)?;
                            let is_valid = rsa_chip.verify_pkcs1v15_signature(
                                ctx,
                                &public_key,
                                &hashed_msg_assigned,
                                &signature,
                            )?;
                            Ok(is_valid)
                        },
                    )?;

                    layouter.assign_region(
                        || "assert is_valid==1 (sha2 disabled)",
                        |region| {
                            let offset = 0;
                            let ctx = &mut RegionCtx::new(region, offset);
                            main_gate.assert_one(ctx, &is_valid)?;
                            Ok(())
                        },
                    )?;
                }

                Ok(())
            }
        }

        fn $setup_fn_name() -> (
            ParamsKZG<Bn256>,
            VerifyingKey<G1Affine>,
            ProvingKey<G1Affine>,
        ) {
            let circuit = $circuit_name::<Fr>::default();
            let k = $k;
            let params = ParamsKZG::<Bn256>::setup(k, OsRng);
            let vk = keygen_vk(&params, &circuit).unwrap();
            let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
            (params, vk, pk)
        }

        fn $prove_fn_name(
            params: &ParamsKZG<Bn256>,
            vk: &VerifyingKey<G1Affine>,
            pk: &ProvingKey<G1Affine>,
        ) {
            let limb_width = $circuit_name::<Fr>::LIMB_WIDTH;
            let num_limbs = $circuit_name::<Fr>::BITS_LEN / $circuit_name::<Fr>::LIMB_WIDTH;
            // 1. Uniformly sample a RSA key pair.
            let mut rng = thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, $circuit_name::<Fr>::BITS_LEN)
                .expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
            // 2. Uniformly sample a message.
            // 3. Compute the SHA256 hash of `msg`.
            let (msg, hashed_msg) = if $sha2_chip_enabled {
                let mut msg: [u8; $msg_bytes] = [0; $msg_bytes];
                for i in 0..$msg_bytes {
                    msg[i] = rng.gen();
                }
                let hashed_msg = Sha256::digest(&msg).to_vec();
                (msg.to_vec(), hashed_msg)
            } else {
                let mut msg: [u8; 32] = [0; 32];
                for i in 0..32 {
                    msg[i] = rng.gen();
                }
                (msg.to_vec(), msg.to_vec())
            };

            // 4. Generate a pkcs1v15 signature.
            let padding = PaddingScheme::PKCS1v15Sign {
                hash: Some(Hash::SHA2_256),
            };
            let mut sign = private_key
                .sign(padding, &hashed_msg)
                .expect("fail to sign a hashed message.");
            sign.reverse();
            let sign_big = BigUint::from_bytes_le(&sign);
            let sign_limbs = decompose_big::<Fr>(sign_big.clone(), num_limbs, limb_width);
            let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

            // 5. Construct `RSAPublicKey` from `n` of `public_key` and fixed `e`.
            let n_big =
                BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
            let n_limbs = decompose_big::<Fr>(n_big.clone(), num_limbs, limb_width);
            let n_unassigned = UnassignedInteger::from(n_limbs.clone());
            let e_fix = RSAPubE::Fix(BigUint::from($circuit_name::<Fr>::DEFAULT_E));
            let public_key = RSAPublicKey::new(n_unassigned, e_fix);

            // 6. Create our circuit!
            let circuit = $circuit_name::<Fr> {
                signature,
                public_key,
                msg,
                _f: PhantomData,
            };

            // 7. Create public inputs
            let column0_public_inputs = if $sha2_chip_enabled {
                hashed_msg
                    .iter()
                    .map(|byte| Fr::from(*byte as u64))
                    .collect::<Vec<Fr>>()
            } else {
                vec![]
            };

            /*{
                let prover =
                    match MockProver::run($k, &circuit, vec![column0_public_inputs.clone()]) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e),
                    };
                assert_eq!(prover.verify(), Ok(()));
            }*/

            // 8. Generate a proof.
            let proof = {
                let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
                create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
                    params,
                    pk,
                    &[circuit],
                    &[&[&column0_public_inputs]],
                    OsRng,
                    &mut transcript,
                )
                .unwrap();
                transcript.finalize()
            };
            // 9. Verify the proof.
            {
                let strategy = SingleStrategy::new(&params);
                let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
                assert!(verify_proof::<_, VerifierGWC<_>, _, _, _>(
                    params,
                    vk,
                    strategy,
                    &[&[&column0_public_inputs]],
                    &mut transcript
                )
                .is_ok());
            }
        }
    };
}

// struct Pkcs1v15BenchCircuit<F: FieldExt> {
//     signature: RSASignature<F>,
//     public_key: RSAPublicKey<F>,
//     msg: Vec<u8>,
//     _f: PhantomData<F>,
// }

// impl<F: FieldExt> Default for Pkcs1v15BenchCircuit<F> {
//     fn default() -> Self {
//         let num_limbs = Self::BITS_LEN / RSAChip::<F>::LIMB_WIDTH;
//         let signature = RSASignature::without_witness(num_limbs);
//         let public_key = RSAPublicKey::without_witness(num_limbs, BigUint::from(Self::DEFAULT_E));
//         Self {
//             signature,
//             public_key,
//             msg: vec![0; 64],
//             _f: PhantomData,
//         }
//     }
// }

// impl<F: FieldExt> Circuit<F> for Pkcs1v15BenchCircuit<F> {
//     type Config = Pkcs1v15BenchConfig;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         Self::default()
//     }

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         // 1. Configure `MainGate`.
//         let main_gate_config = MainGate::<F>::configure(meta);
//         // 2. Compute bit length parameters by calling `RSAChip::<F>::compute_range_lens` function.
//         let (composition_bit_lens, overflow_bit_lens) =
//             RSAChip::<F>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH);
//         // 3. Configure `RangeChip`.
//         let range_config = RangeChip::<F>::configure(
//             meta,
//             &main_gate_config,
//             composition_bit_lens,
//             overflow_bit_lens,
//         );
//         // 4. Configure `BigIntConfig`.
//         let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
//         // 5. Configure `RSAConfig`.
//         let rsa_config = RSAConfig::new(bigint_config);
//         // 6. Configure `Sha256Config`.
//         let table16_congig = Table16Chip::configure(meta);
//         let sha256_config =
//             Sha256Config::new(main_gate_config, range_config, table16_congig, 64 * 4);
//         Self::Config {
//             rsa_config,
//             sha256_config,
//         }
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
//     ) -> Result<(), Error> {
//         let rsa_chip = self.rsa_chip(config.rsa_config);
//         let sha256_chip = self.sha256_chip(config.sha256_config);
//         let bigint_chip = rsa_chip.bigint_chip();
//         let main_gate = rsa_chip.main_gate();
//         // 1. Assign a public key and signature.
//         let (public_key, signature) = layouter.assign_region(
//             || "rsa signature with hash test using 2048 bits public keys",
//             |region| {
//                 let offset = 0;
//                 let ctx = &mut RegionCtx::new(region, offset);
//                 let sign = rsa_chip.assign_signature(ctx, self.signature.clone())?;
//                 let public_key = rsa_chip.assign_public_key(ctx, self.public_key.clone())?;
//                 Ok((public_key, sign))
//             },
//         )?;
//         // 2. Create a RSA signature verifier from `RSAChip` and `Sha256BitChip`
//         let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
//         // 3. Receives the verification result and the resulting hash of `self.msg` from `RSASignatureVerifier`.
//         let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
//             layouter.namespace(|| "verify pkcs1v15 signature"),
//             &public_key,
//             &self.msg,
//             &signature,
//         )?;
//         // 4. Expose the RSA public key as public input.
//         for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
//             main_gate.expose_public(
//                 layouter.namespace(|| format!("expose {} th public key limb", i)),
//                 limb.assigned_val(),
//                 i,
//             )?;
//         }
//         let num_limb_n = Self::BITS_LEN / RSAChip::<F>::LIMB_WIDTH;
//         // 5. Expose the resulting hash as public input.
//         for (i, val) in hashed_msg.into_iter().enumerate() {
//             main_gate.expose_public(
//                 layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
//                 val,
//                 num_limb_n + i,
//             )?;
//         }
//         // 6. The verification result must be one.
//         layouter.assign_region(
//             || "assert is_valid==1",
//             |region| {
//                 let offset = 0;
//                 let ctx = &mut RegionCtx::new(region, offset);
//                 main_gate.assert_one(ctx, &is_valid)?;
//                 Ok(())
//             },
//         )?;
//         // Create lookup tables for range check in `range_chip`.
//         let range_chip = bigint_chip.range_chip();
//         range_chip.load_table(&mut layouter)?;
//         Ok(())
//     }
// }

impl_pkcs1v15_bench_circuit!(
    Pkcs1v15_1024_64EnabledBenchCircuit,
    setup_pkcs1v15_1024_64_enabled,
    prove_pkcs1v15_1024_64_enabled,
    17,
    1024,
    64,
    true
);

fn bench_pkcs1v15_1024_enabled(c: &mut Criterion) {
    let (params_64, vk_64, pk_64) = setup_pkcs1v15_1024_64_enabled();
    let mut group = c.benchmark_group("pkcs1v15, 1024 bit public key, sha2 enabled");
    group.sample_size(10);
    group.bench_function("message 64 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_64_enabled(&params_64, &vk_64, &pk_64))
    });
    group.finish();
}

criterion_group!(benches, bench_pkcs1v15_1024_enabled);
criterion_main!(benches);
