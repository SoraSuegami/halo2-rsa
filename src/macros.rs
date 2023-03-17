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
use halo2_dynamic_sha256::{Field, Sha256CompressionConfig, Sha256DynamicConfig};
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
    ($config_name:ident, $circuit_name:ident, $setup_fn_name:ident, $prove_fn_name:ident, $bits_len:expr, $msg_len:expr, $num_sha2_comp:expr, $k:expr, $sha2_chip_enabled:expr) => {
        #[derive(Debug, Clone)]
        struct $config_name<F: Field> {
            rsa_config: RSAConfig<F>,
            sha256_config: Option<Sha256DynamicConfig<F>>,
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
            const NUM_ADVICE: usize = 80;
            const NUM_FIXED: usize = 1;
            const NUM_LOOKUP_ADVICE: usize = 8;
            const LOOKUP_BITS: usize = 12;
            const NUM_SHA2_COMP: usize = $num_sha2_comp;
        }

        impl<F: Field> Default for $circuit_name<F> {
            fn default() -> Self {
                let num_limbs = Self::BITS_LEN / 64;
                let signature = RSASignature::without_witness();
                let public_key = RSAPublicKey::without_witness(BigUint::from(Self::DEFAULT_E));
                let msg = if $sha2_chip_enabled {
                    vec![0; $msg_len - 9]
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
                let sha256_config = if $sha2_chip_enabled {
                    let sha256_bit_configs = (0..Self::NUM_SHA2_COMP)
                        .map(|_| Sha256CompressionConfig::configure(meta))
                        .collect();
                    Some(Sha256DynamicConfig::construct(
                        sha256_bit_configs,
                        Self::MSG_LEN,
                        range_config,
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
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let biguint_config = config.rsa_config.biguint_config();
                let limb_bits = 64;
                let num_limbs = Self::BITS_LEN / limb_bits;

                biguint_config.range().load_lookup_table(&mut layouter)?;
                let mut first_pass = SKIP_FIRST_PASS;
                layouter.assign_region(
                    || "pkcs1v15 signature verification",
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
                        let sign = config
                            .rsa_config
                            .assign_signature(ctx, self.signature.clone())?;
                        let public_key = config
                            .rsa_config
                            .assign_public_key(ctx, self.public_key.clone())?;
                        if $sha2_chip_enabled {
                            let verifier = RSASignatureVerifier::new(
                                config.rsa_config.clone(),
                                config.sha256_config.clone().unwrap(),
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
                        } else {
                            let gate = config.rsa_config.gate();
                            let mut msg = self.msg.clone();
                            msg.reverse();
                            let hash_u64s = msg.chunks(limb_bits / 8).map(|limbs| {
                                let mut sum = 0u64;
                                for (i, limb) in limbs.into_iter().enumerate() {
                                    sum += (*limb as u64) << (8 * i);
                                }
                                F::from(sum)
                            });
                            let assigned_msg = hash_u64s
                                .map(|v| gate.load_witness(ctx, Value::known(v)))
                                .collect::<Vec<AssignedValue<F>>>();
                            let is_valid = config.rsa_config.verify_pkcs1v15_signature(
                                ctx,
                                &public_key,
                                &assigned_msg,
                                &sign,
                            )?;
                            config
                                .rsa_config
                                .gate()
                                .assert_is_const(ctx, &is_valid, F::one());
                        }
                        biguint_config.range().finalize(ctx);
                        {
                            println!("total advice cells: {}", ctx.total_advice);
                            let const_rows = ctx.total_fixed + 1;
                            println!("maximum rows used by a fixed column: {const_rows}");
                            println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                        }
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
                let mut msg: [u8; $msg_len - 9] = [0; $msg_len - 9];
                for i in 0..($msg_len - 9) {
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
    };
}
