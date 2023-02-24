use crate::{
    AssignedBigUint, AssignedRSAPubE, AssignedRSAPublicKey, AssignedRSASignature, BigUintConfig,
    BigUintInstructions, Fresh, RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature,
    RSASignatureVerifier,
};
use halo2_base::halo2_proofs::{
    circuit::{Cell, Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, Error},
    plonk::{Circuit, Column, ConstraintSystem, Instance},
};
use halo2_base::utils::fe_to_bigint;
use halo2_base::ContextParams;
use halo2_base::QuantumCell;
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context,
};
use halo2_dynamic_sha256::{Field, Sha256BitConfig, Sha256DynamicConfig};
use halo2_ecc::bigint::{
    big_is_equal, big_is_zero, big_less_than, carry_mod, mul_no_carry, negative, select, sub,
    CRTInteger, FixedCRTInteger, FixedOverflowInteger, OverflowInteger,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};
use rand::rngs::OsRng;
use std::marker::PhantomData;

use rand::{thread_rng, Rng};
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

#[macro_export]
macro_rules! impl_pkcs1v15_basic_circuit {
    ($config_name:ident, $circuit_name:ident, $setup_fn_name:ident, $prove_fn_name:ident, $bits_len:expr, $msg_len:expr, $k:expr, $sha2_chip_enabled:expr) => {
        #[derive(Debug, Clone)]
        struct $config_name<F: Field> {
            rsa_config: RSAConfig<F>,
            sha256_config: Sha256DynamicConfig<F>,
        }

        struct $circuit_name<F: Field> {
            signature: RSASignature<F>,
            public_key: RSAPublicKey<F>,
            msg: Vec<u8>,
            _f: PhantomData<F>,
        }

        impl<F: Field> $circuit_name<F> {
            const BITS_LEN: usize = $bits_len;
            const MSG_LEN: usize = $msg_len;
            const LIMB_WIDTH: usize = 64;
            const EXP_LIMB_BITS: usize = 5;
            const DEFAULT_E: u128 = 65537;
            const NUM_ADVICE: usize = 50;
            const NUM_FIXED: usize = 1;
            const NUM_LOOKUP_ADVICE: usize = 4;
            const LOOKUP_BITS: usize = 12;
        }

        impl<F: Field> Default for $circuit_name<F> {
            fn default() -> Self {
                let num_limbs = Self::BITS_LEN / 64;
                let signature = RSASignature::without_witness();
                let public_key = RSAPublicKey::without_witness(BigUint::from(Self::DEFAULT_E));
                let msg = if $sha2_chip_enabled {
                    vec![0; $msg_len]
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

        impl<F: Field> Circuit<F> for $circuit_name<F> {
            type Config = $config_name<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                unimplemented!();
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let range_config = RangeConfig::configure(
                    meta,
                    Vertical,
                    &[Self::NUM_ADVICE],
                    &[Self::NUM_LOOKUP_ADVICE],
                    Self::NUM_FIXED,
                    Self::LOOKUP_BITS,
                    0,
                    $k,
                );
                let bigint_config = BigUintConfig::construct(range_config.clone(), 64);
                let rsa_config =
                    RSAConfig::construct(bigint_config, Self::BITS_LEN, Self::EXP_LIMB_BITS);
                let sha256_bit_config = Sha256BitConfig::configure(meta);
                let sha256_config = Sha256DynamicConfig::construct(
                    sha256_bit_config,
                    Self::MSG_LEN + 64,
                    range_config,
                );
                Self::Config {
                    rsa_config,
                    sha256_config,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let biguint_config = config.rsa_config.biguint_config();
                let limb_bits = 64;
                let num_limbs = Self::BITS_LEN / limb_bits;

                biguint_config.range().load_lookup_table(&mut layouter)?;
                let mut first_pass = SKIP_FIRST_PASS;
                layouter.assign_region(
                    || "random rsa modpow test with 2048 bits public keys",
                    |region| {
                        if first_pass {
                            first_pass = false;
                            return Ok(());
                        }

                        let mut aux = biguint_config.new_context(region);
                        let ctx = &mut aux;
                        let hashed_msg = Sha256::digest(&self.msg);
                        let padding = PaddingScheme::PKCS1v15Sign {
                            hash: Some(Hash::SHA2_256),
                        };
                        // let mut sign = self
                        //     .private_key
                        //     .sign(padding, &hashed_msg)
                        //     .expect("fail to sign a hashed message.");
                        // sign.reverse();
                        // let sign_big = BigUint::from_bytes_le(&sign);
                        let sign = config
                            .rsa_config
                            .assign_signature(ctx, self.signature.clone())?;
                        // let n_big = BigUint::from_radix_le(
                        //     &self.public_key.n().clone().to_radix_le(16),
                        //     16,
                        // )
                        // .unwrap();
                        // let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                        let public_key = config
                            .rsa_config
                            .assign_public_key(ctx, self.public_key.clone())?;
                        let verifier = RSASignatureVerifier::new(
                            config.rsa_config.clone(),
                            config.sha256_config.clone(),
                        );
                        let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                            ctx,
                            &public_key,
                            &self.msg,
                            &sign,
                        )?;
                        biguint_config
                            .gate()
                            .assert_is_const(ctx, &is_valid, F::one());
                        biguint_config.range().finalize(ctx);
                        {
                            println!("total advice cells: {}", ctx.total_advice);
                            let const_rows = ctx.total_fixed + 1;
                            println!("maximum rows used by a fixed column: {const_rows}");
                            println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                        }
                        let public_key_cells = public_key
                            .n
                            .limbs()
                            .into_iter()
                            .map(|v| v.cell())
                            .collect::<Vec<Cell>>();
                        let hashed_msg_cells = hashed_msg
                            .into_iter()
                            .map(|v| v.cell())
                            .collect::<Vec<Cell>>();
                        Ok(())
                    },
                )?;
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
            let limb_bits = 64;
            let num_limbs = $bits_len / 64;
            // 1. Uniformly sample a RSA key pair.
            let mut rng = thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, $circuit_name::<Fr>::BITS_LEN)
                .expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
            // 2. Uniformly sample a message.
            // 3. Compute the SHA256 hash of `msg`.
            let (msg, hashed_msg) = if $sha2_chip_enabled {
                let mut msg: [u8; $msg_len] = [0; $msg_len];
                for i in 0..$msg_len {
                    msg[i] = rng.gen();
                }
                let hashed_msg = Sha256::digest(&msg).to_vec();
                (msg.to_vec(), hashed_msg)
            } else {
                let mut msg: [u8; 32] = [0; 32];
                for i in 0..32 {
                    msg[i] = rng.gen();
                }
                let hashed_msg = Sha256::digest(&msg).to_vec();
                (hashed_msg.clone(), hashed_msg)
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
            let signature = RSASignature::new(Value::known(sign_big));

            // 5. Construct `RSAPublicKey` from `n` of `public_key` and fixed `e`.
            let n_big =
                BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
            let e_fix = RSAPubE::Fix(BigUint::from($circuit_name::<Fr>::DEFAULT_E));
            let public_key = RSAPublicKey::new(Value::known(n_big), e_fix);

            // 6. Create our circuit!
            let circuit = $circuit_name::<Fr> {
                signature,
                public_key,
                msg,
                _f: PhantomData,
            };

            let prover = match MockProver::run($k, &circuit, vec![]) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            prover.verify().unwrap();

            // 7. Generate a proof.
            let proof = {
                let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
                create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
                    params,
                    pk,
                    &[circuit],
                    &[&[]],
                    OsRng,
                    &mut transcript,
                )
                .unwrap();
                transcript.finalize()
            };
            // // 9. Verify the proof.
            // {
            //     let strategy = SingleStrategy::new(&params);
            //     let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            //     assert!(verify_proof::<_, VerifierGWC<_>, _, _, _>(
            //         params,
            //         vk,
            //         strategy,
            //         &[&[&[]]],
            //         &mut transcript
            //     )
            //     .is_ok());
            // }
        }
    }; // ($config_name:ident, $circuit_name:ident, $setup_fn_name:ident, $prove_fn_name:ident, $k:expr, $n_bits:expr, $msg_bytes:expr, $sha2_chip_enabled:expr) => {
       //     #[derive(Debug, Clone)]
       //     struct $config_name<F: Field> {
       //         rsa_config: RSAConfig,
       //         sha256_config: Option<Sha256DynamicConfig<F>>,
       //     }

       //     struct $circuit_name<F: Field> {
       //         signature: RSASignature<F>,
       //         public_key: RSAPublicKey<F>,
       //         msg: Vec<u8>,
       //         _f: PhantomData<F>,
       //     }

       //     impl<F: Field> Default for $circuit_name<F> {
       //         fn default() -> Self {
       //             let num_limbs = Self::BITS_LEN / RSAChip::<F>::LIMB_WIDTH;
       //             let signature = RSASignature::without_witness(num_limbs);
       //             let public_key =
       //                 RSAPublicKey::without_witness(num_limbs, BigUint::from(Self::DEFAULT_E));
       //             let msg = if $sha2_chip_enabled {
       //                 vec![0; $msg_bytes]
       //             } else {
       //                 vec![0; 32]
       //             };
       //             Self {
       //                 signature,
       //                 public_key,
       //                 msg,
       //                 _f: PhantomData,
       //             }
       //         }
       //     }

       //     impl<F: Field> $circuit_name<F> {
       //         const BITS_LEN: usize = $n_bits;
       //         const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH;
       //         const EXP_LIMB_BITS: usize = 5;
       //         const DEFAULT_E: u128 = 65537;
       //         fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
       //             RSAChip::new(config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
       //         }
       //         fn sha256_chip(&self, config: Sha256DynamicConfig<F>) -> Sha256DynamicChip<F> {
       //             Sha256DynamicChip::new(config)
       //         }
       //     }

       //     impl<F: Field> Circuit<F> for $circuit_name<F> {
       //         type Config = $config_name<F>;
       //         type FloorPlanner = SimpleFloorPlanner;

       //         fn without_witnesses(&self) -> Self {
       //             Self::default()
       //         }

       //         fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
       //             // 1. Configure `MainGate`.
       //             let main_gate_config = MainGate::<F>::configure(meta);
       //             // 2. Compute bit length parameters by calling `RSAChip::<F>::compute_range_lens` function.
       //             let (mut composition_bit_lens, mut overflow_bit_lens) =
       //                 RSAChip::<F>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH);
       //             // let (mut sha_composition_bit_lens, mut sha_overflow_bit_lens) =
       //             //     Sha256DynamicChip::<F>::compute_range_lens();
       //             // composition_bit_lens.append(&mut sha_composition_bit_lens);
       //             // overflow_bit_lens.append(&mut sha_overflow_bit_lens);
       //             // 3. Configure `RangeChip`.
       //             let range_config = RangeChip::<F>::configure(
       //                 meta,
       //                 &main_gate_config,
       //                 composition_bit_lens,
       //                 overflow_bit_lens,
       //             );
       //             // 4. Configure `BigIntConfig`.
       //             let bigint_config =
       //                 BigIntConfig::new(range_config.clone(), main_gate_config.clone());
       //             // 5. Configure `RSAConfig`.
       //             let rsa_config = RSAConfig::new(bigint_config);
       //             // 6. Configure `Sha256Config`.
       //             let sha256_config = if $sha2_chip_enabled {
       //                 let sha256_bit_config = Sha256BitConfig::configure(meta);
       //                 let sha256_config = Sha256DynamicChip::configure(
       //                     meta,
       //                     main_gate_config,
       //                     sha256_bit_config,
       //                     $msg_bytes + 64,
       //                 );
       //                 Some(sha256_config)
       //             } else {
       //                 None
       //             };
       //             Self::Config {
       //                 rsa_config,
       //                 sha256_config,
       //             }
       //         }

       //         fn synthesize(
       //             &self,
       //             config: Self::Config,
       //             mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
       //         ) -> Result<(), Error> {
       //             let rsa_chip = self.rsa_chip(config.rsa_config);
       //             let bigint_chip = rsa_chip.bigint_chip();
       //             let main_gate = rsa_chip.main_gate();
       //             // Create lookup tables for range check in `range_chip`.
       //             let range_chip = bigint_chip.range_chip();
       //             range_chip.load_table(&mut layouter)?;

       //             // 1. Assign a public key and signature.
       //             let (public_key, signature) = layouter.assign_region(
       //                 || "rsa signature with hash test",
       //                 |region| {
       //                     let offset = 0;
       //                     let ctx = &mut RegionCtx::new(region, offset);
       //                     let sign = rsa_chip.assign_signature(ctx, self.signature.clone())?;
       //                     let public_key =
       //                         rsa_chip.assign_public_key(ctx, self.public_key.clone())?;
       //                     Ok((public_key, sign))
       //                 },
       //             )?;
       //             if $sha2_chip_enabled {
       //                 let sha256_chip = self.sha256_chip(config.sha256_config.unwrap());
       //                 // 2. Create a RSA signature verifier from `RSAChip` and `Sha256BitChip`
       //                 let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
       //                 // 3. Receives the verification result and the resulting hash of `self.msg` from `RSASignatureVerifier`.
       //                 let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
       //                     layouter.namespace(|| "verify pkcs1v15 signature"),
       //                     &public_key,
       //                     &self.msg,
       //                     &signature,
       //                 )?;

       //                 // 4. Expose the RSA public key as public input.
       //                 // for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
       //                 //     main_gate.expose_public(
       //                 //         layouter.namespace(|| format!("expose {} th public key limb", i)),
       //                 //         limb.assigned_val(),
       //                 //         i,
       //                 //     )?;
       //                 // }
       //                 // let num_limb_n = Self::BITS_LEN / RSAChip::<F>::LIMB_WIDTH;

       //                 //5. Expose the resulting hash as public input.
       //                 // for (i, val) in hashed_msg.into_iter().enumerate() {
       //                 //     main_gate.expose_public(
       //                 //         layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
       //                 //         val,
       //                 //         num_limb_n + i,
       //                 //     )?;
       //                 // }
       //                 // 6. The verification result must be one.
       //                 layouter.assign_region(
       //                     || "assert is_valid==1 (sha2 enabled)",
       //                     |region| {
       //                         let offset = 0;
       //                         let ctx = &mut RegionCtx::new(region, offset);
       //                         main_gate.assert_one(ctx, &is_valid)?;
       //                         Ok(())
       //                     },
       //                 )?;
       //             } else {
       //                 let is_valid = layouter.assign_region(
       //                     || "get is_valid (sha2 disabled)",
       //                     |region| {
       //                         let offset = 0;
       //                         let ctx = &mut RegionCtx::new(region, offset);
       //                         let mut hashed_msg = self.msg.clone();
       //                         hashed_msg.reverse();
       //                         let hashed_msg_big = BigUint::from_bytes_le(&hashed_msg);
       //                         let hashed_msg_limbs = decompose_big::<F>(
       //                             hashed_msg_big.clone(),
       //                             4,
       //                             RSAChip::<F>::LIMB_WIDTH,
       //                         );
       //                         let hashed_msg_unassigned = UnassignedInteger::from(hashed_msg_limbs);
       //                         let hashed_msg_assigned =
       //                             bigint_chip.assign_integer(ctx, hashed_msg_unassigned)?;
       //                         let is_valid = rsa_chip.verify_pkcs1v15_signature(
       //                             ctx,
       //                             &public_key,
       //                             &hashed_msg_assigned,
       //                             &signature,
       //                         )?;
       //                         Ok(is_valid)
       //                     },
       //                 )?;

       //                 // for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
       //                 //     main_gate.expose_public(
       //                 //         layouter.namespace(|| format!("expose {} th public key limb", i)),
       //                 //         limb.assigned_val(),
       //                 //         i,
       //                 //     )?;
       //                 // }

       //                 layouter.assign_region(
       //                     || "assert is_valid==1 (sha2 disabled)",
       //                     |region| {
       //                         let offset = 0;
       //                         let ctx = &mut RegionCtx::new(region, offset);
       //                         main_gate.assert_one(ctx, &is_valid)?;
       //                         Ok(())
       //                     },
       //                 )?;
       //             }

       //             Ok(())
       //         }
       //     }

       //     fn $setup_fn_name() -> (
       //         ParamsKZG<Bn256>,
       //         VerifyingKey<G1Affine>,
       //         ProvingKey<G1Affine>,
       //     ) {
       //         let circuit = $circuit_name::<Fr>::default();
       //         let k = $k;
       //         let params = ParamsKZG::<Bn256>::setup(k, OsRng);
       //         let vk = keygen_vk(&params, &circuit).unwrap();
       //         let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
       //         (params, vk, pk)
       //     }

       //     fn $prove_fn_name(
       //         params: &ParamsKZG<Bn256>,
       //         vk: &VerifyingKey<G1Affine>,
       //         pk: &ProvingKey<G1Affine>,
       //     ) {
       //         let limb_width = $circuit_name::<Fr>::LIMB_WIDTH;
       //         let num_limbs = $circuit_name::<Fr>::BITS_LEN / $circuit_name::<Fr>::LIMB_WIDTH;
       //         // 1. Uniformly sample a RSA key pair.
       //         let mut rng = thread_rng();
       //         let private_key = RsaPrivateKey::new(&mut rng, $circuit_name::<Fr>::BITS_LEN)
       //             .expect("failed to generate a key");
       //         let public_key = RsaPublicKey::from(&private_key);
       //         // 2. Uniformly sample a message.
       //         // 3. Compute the SHA256 hash of `msg`.
       //         let (msg, hashed_msg) = if $sha2_chip_enabled {
       //             let mut msg: [u8; $msg_bytes] = [0; $msg_bytes];
       //             for i in 0..$msg_bytes {
       //                 msg[i] = rng.gen();
       //             }
       //             let hashed_msg = Sha256::digest(&msg).to_vec();
       //             (msg.to_vec(), hashed_msg)
       //         } else {
       //             let mut msg: [u8; 32] = [0; 32];
       //             for i in 0..32 {
       //                 msg[i] = rng.gen();
       //             }
       //             let hashed_msg = Sha256::digest(&msg).to_vec();
       //             (hashed_msg.clone(), hashed_msg)
       //         };

       //         // 4. Generate a pkcs1v15 signature.
       //         let padding = PaddingScheme::PKCS1v15Sign {
       //             hash: Some(Hash::SHA2_256),
       //         };
       //         let mut sign = private_key
       //             .sign(padding, &hashed_msg)
       //             .expect("fail to sign a hashed message.");
       //         sign.reverse();
       //         let sign_big = BigUint::from_bytes_le(&sign);
       //         let sign_limbs = decompose_big::<Fr>(sign_big.clone(), num_limbs, limb_width);
       //         let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

       //         // 5. Construct `RSAPublicKey` from `n` of `public_key` and fixed `e`.
       //         let n_big =
       //             BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
       //         let n_limbs = decompose_big::<Fr>(n_big.clone(), num_limbs, limb_width);
       //         let n_unassigned = UnassignedInteger::from(n_limbs.clone());
       //         let e_fix = RSAPubE::Fix(BigUint::from($circuit_name::<Fr>::DEFAULT_E));
       //         let public_key = RSAPublicKey::new(n_unassigned, e_fix);

       //         // 6. Create our circuit!
       //         // Compute the randomness from the hashed_msg.
       //         let mut seed = [0; 64];
       //         for idx in 0..32 {
       //             seed[idx] = hashed_msg[idx];
       //         }
       //         let circuit = $circuit_name::<Fr> {
       //             signature,
       //             public_key,
       //             msg,
       //             _f: PhantomData,
       //         };

       //         let prover = match MockProver::run($k, &circuit, vec![vec![]]) {
       //             Ok(prover) => prover,
       //             Err(e) => panic!("{:#?}", e),
       //         };
       //         prover.verify().unwrap();

       //         // 7. Create public inputs
       //         //let mut column0_public_inputs = n_limbs;
       //         // if $sha2_chip_enabled {
       //         //     let mut hash_fes = hashed_msg
       //         //         .iter()
       //         //         .map(|byte| Fr::from(*byte as u64))
       //         //         .collect::<Vec<Fr>>();
       //         //     column0_public_inputs.append(&mut hash_fes);
       //         // }

       //         /*{
       //             let prover =
       //                 match MockProver::run($k, &circuit, vec![column0_public_inputs.clone()]) {
       //                     Ok(prover) => prover,
       //                     Err(e) => panic!("{:#?}", e),
       //                 };
       //             assert_eq!(prover.verify(), Ok(()));
       //         }*/

       //         // 8. Generate a proof.
       //         let proof = {
       //             let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
       //             create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
       //                 params,
       //                 pk,
       //                 &[circuit],
       //                 &[&[&[]]],
       //                 OsRng,
       //                 &mut transcript,
       //             )
       //             .unwrap();
       //             transcript.finalize()
       //         };
       //         // 9. Verify the proof.
       //         {
       //             let strategy = SingleStrategy::new(&params);
       //             let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
       //             assert!(verify_proof::<_, VerifierGWC<_>, _, _, _>(
       //                 params,
       //                 vk,
       //                 strategy,
       //                 &[&[&[]]],
       //                 &mut transcript
       //             )
       //             .is_ok());
       //         }
       //     }
       // };
}
