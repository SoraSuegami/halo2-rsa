pub mod big_integer;
mod chip;
mod instructions;
use big_integer::*;
pub use chip::*;
use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value, plonk::Error};
pub use instructions::*;
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};
use num_bigint::BigUint;

#[derive(Clone, Debug)]
pub enum RSAPubE<F: FieldExt> {
    Var(UnassignedInteger<F>),
    Fix(BigUint),
}

#[derive(Clone, Debug)]
pub enum AssignedRSAPubE<F: FieldExt> {
    Var(AssignedInteger<F, Fresh>),
    Fix(BigUint),
}

#[derive(Clone, Debug)]
pub struct RSAPublicKey<F: FieldExt> {
    n: UnassignedInteger<F>,
    e: RSAPubE<F>,
}

impl<F: FieldExt> RSAPublicKey<F> {
    pub fn new(n: UnassignedInteger<F>, e: RSAPubE<F>) -> Self {
        Self { n, e }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<F: FieldExt> {
    n: AssignedInteger<F, Fresh>,
    e: AssignedRSAPubE<F>,
}

impl<F: FieldExt> AssignedRSAPublicKey<F> {
    pub fn new(n: AssignedInteger<F, Fresh>, e: AssignedRSAPubE<F>) -> Self {
        Self { n, e }
    }
}

#[derive(Clone, Debug)]
pub struct RSASignature<F: FieldExt> {
    c: UnassignedInteger<F>,
}

impl<F: FieldExt> RSASignature<F> {
    pub fn new(c: UnassignedInteger<F>) -> Self {
        Self { c }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedRSASignature<F: FieldExt> {
    c: AssignedInteger<F, Fresh>,
}

impl<F: FieldExt> AssignedRSASignature<F> {
    pub fn new(c: AssignedInteger<F, Fresh>) -> Self {
        Self { c }
    }
}

use eth_types::Field;
use halo2wrong::halo2::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem},
};
use zkevm_circuits::sha256_circuit::sha256_bit::{Sha256BitChip, Sha256BitConfig};

#[derive(Clone, Debug)]
pub struct RSASignatureVerifier<F: Field> {
    rsa_chip: RSAChip<F>,
    sha256_chip: Sha256BitChip<F>,
}

impl<F: Field> RSASignatureVerifier<F> {
    pub fn new(rsa_chip: RSAChip<F>, sha256_chip: Sha256BitChip<F>) -> Self {
        Self {
            rsa_chip,
            sha256_chip,
        }
    }

    pub fn verify_pkcs1v15_signature(
        &mut self,
        mut layouter: impl Layouter<F>,
        public_key: &AssignedRSAPublicKey<F>,
        msg: &[u8],
        signature: &AssignedRSASignature<F>,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        let inputs = vec![msg.to_vec()];
        let hashed_bytes = self
            .sha256_chip
            .digest(layouter.namespace(|| "sha256"), &inputs)?;
        let mut hashed_bytes = hashed_bytes[0].clone();
        hashed_bytes.reverse();
        let bytes_len = hashed_bytes.len();
        let limb_bytes = RSAChip::<F>::LIMB_WIDTH / 8;
        let rsa_chip = self.rsa_chip.clone();
        let main_gate = rsa_chip.main_gate();
        let is_valid = layouter.assign_region(
            || "verify pkcs1v15 signature",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut assigned_limbs = Vec::with_capacity(bytes_len / limb_bytes);
                for i in 0..(bytes_len / limb_bytes) {
                    let mut limb_val = main_gate.assign_constant(ctx, F::zero())?;
                    for j in 0..limb_bytes {
                        let coeff = main_gate
                            .assign_constant(ctx, big_to_fe(BigUint::from(1usize) << (8 * j)))?;
                        limb_val = main_gate.mul_add(
                            ctx,
                            &coeff,
                            &hashed_bytes[limb_bytes * i + j],
                            &limb_val,
                        )?;
                    }
                    assigned_limbs.push(AssignedLimb::from(limb_val));
                }
                let hashed_msg = AssignedInteger::new(&assigned_limbs);
                let is_sign_valid =
                    rsa_chip.verify_pkcs1v15_signature(ctx, public_key, &hashed_msg, signature)?;
                Ok(is_sign_valid)
            },
        )?;
        hashed_bytes.reverse();
        Ok((is_valid, hashed_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2wrong::curves::{
        bn256::Fr as BnFr,
        pasta::{Fp as PastaFp, Fq as PastaFq},
    };
    use halo2wrong::halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};
    use rsa::*;
    use sha2::{Digest, Sha256};
    use std::marker::PhantomData;

    struct RSASignatureTest {}

    macro_rules! impl_rsa_signature_test_circuit {
        ($config_name:ident, $circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $should_be_error:expr, $( $synth:tt )*) => {
            #[derive(Debug,Clone)]
            struct $config_name<F: Field> {
                rsa_config: RSAConfig,
                sha256_config: Sha256BitConfig<F>
            }

            struct $circuit_name<F: Field> {
                private_key: RsaPrivateKey,
                public_key: RsaPublicKey,
                msg: Vec<u8>,
                _f: PhantomData<F>
            }

            impl<F: Field> $circuit_name<F> {
                const BITS_LEN:usize = $bits_len;
                const LIMB_WIDTH:usize = RSAChip::<F>::LIMB_WIDTH;
                const EXP_LIMB_BITS:usize = 5;
                const DEFAULT_E: u128 = 65537;
                fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
                    RSAChip::new(config, Self::BITS_LEN,Self::EXP_LIMB_BITS)
                }
                fn sha256_chip(&self, config: Sha256BitConfig<F>) -> Sha256BitChip<F> {
                    Sha256BitChip::new(config)
                }
            }

            impl<F: Field> Circuit<F> for $circuit_name<F> {
                type Config = $config_name<F>;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let main_gate_config = MainGate::<F>::configure(meta);
                    let (composition_bit_lens, overflow_bit_lens) =
                        RSAChip::<F>::compute_range_lens(
                            Self::BITS_LEN / Self::LIMB_WIDTH,
                        );
                    let range_config = RangeChip::<F>::configure(
                        meta,
                        &main_gate_config,
                        composition_bit_lens,
                        overflow_bit_lens,
                    );
                    let bigint_config = BigIntConfig::new(range_config, main_gate_config);
                    let rsa_config = RSAConfig::new(bigint_config);
                    let sha256_config = Sha256BitConfig::<F>::configure(meta,F::from(123456));
                    Self::Config {
                        rsa_config,
                        sha256_config
                    }
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                use halo2wrong::halo2::dev::MockProver;
                fn run<F: Field>() {
                    let mut rng = thread_rng();
                    let private_key = RsaPrivateKey::new(&mut rng, $circuit_name::<F>::BITS_LEN).expect("failed to generate a key");
                    let public_key = RsaPublicKey::from(&private_key);
                    let n = BigUint::from_radix_le(&public_key.n().to_radix_le(16),16).unwrap();
                    let mut msg:[u8;128] = [0;128];
                    for i in 0..128 {
                        msg[i] = rng.gen();
                    }
                    let hashed_msg = Sha256::digest(&msg);
                    let circuit = $circuit_name::<F> {
                        private_key,
                        public_key,
                        msg: msg.to_vec(),
                        _f: PhantomData
                    };
                    let num_limbs = $circuit_name::<F>::BITS_LEN / $circuit_name::<F>::LIMB_WIDTH;
                    let limb_width = $circuit_name::<F>::LIMB_WIDTH;
                    let n_fes = decompose_big::<F>(n, num_limbs, limb_width);
                    let mut hash_fes = hashed_msg.iter().map(|byte| F::from(*byte as u64)).collect::<Vec<F>>();
                    let mut column0_public_inputs = n_fes;
                    column0_public_inputs.append(&mut hash_fes);
                    let public_inputs = vec![column0_public_inputs];
                    let k = 17;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }
                run::<BnFr>();
            }
        };
    }

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig,
        TestRSASignatureWithHashCircuit,
        test_rsa_signature_with_hash_circuit,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config.rsa_config);
            let sha256_chip = self.sha256_chip(config.sha256_config);
            let bigint_chip = rsa_chip.bigint_chip();
            let main_gate = rsa_chip.main_gate();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let hashed_msg = Sha256::digest(&self.msg);
                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let mut sign = self
                        .private_key
                        .sign(padding, &hashed_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    Ok((public_key, sign))
                },
            )?;
            let mut verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
            let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                layouter.namespace(|| "verify pkcs1v15 signature"),
                &public_key,
                &self.msg,
                &signature,
            )?;
            for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th public key limb", i)),
                    limb.assigned_val(),
                    i,
                )?;
            }
            let num_limb_n = public_key.n.num_limbs();
            for (i, val) in hashed_msg.into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                    val,
                    num_limb_n + i,
                )?;
            }
            layouter.assign_region(
                || "assert is_valid==1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig2,
        TestRSASignatureWithHashCircuit2,
        test_rsa_signature_with_hash_circuit2,
        1024,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config.rsa_config);
            let sha256_chip = self.sha256_chip(config.sha256_config);
            let bigint_chip = rsa_chip.bigint_chip();
            let main_gate = rsa_chip.main_gate();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 1024 bits public keys",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let hashed_msg = Sha256::digest(&self.msg);
                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let mut sign = self
                        .private_key
                        .sign(padding, &hashed_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    Ok((public_key, sign))
                },
            )?;
            let mut verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
            let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                layouter.namespace(|| "verify pkcs1v15 signature"),
                &public_key,
                &self.msg,
                &signature,
            )?;
            for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th public key limb", i)),
                    limb.assigned_val(),
                    i,
                )?;
            }
            let num_limb_n = public_key.n.num_limbs();
            for (i, val) in hashed_msg.into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                    val,
                    num_limb_n + i,
                )?;
            }
            layouter.assign_region(
                || "assert is_valid==1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig3,
        TestRSASignatureWithHashCircuit3,
        test_rsa_signature_with_hash_circuit3,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config.rsa_config);
            let sha256_chip = self.sha256_chip(config.sha256_config);
            let bigint_chip = rsa_chip.bigint_chip();
            let main_gate = rsa_chip.main_gate();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys: invalid signed message case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let hashed_msg = Sha256::digest(&self.msg);
                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let mut rng = thread_rng();
                    let invalid_private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
                    let mut sign = invalid_private_key
                        .sign(padding, &hashed_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    Ok((public_key, sign))
                },
            )?;
            let mut verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
            let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                layouter.namespace(|| "verify pkcs1v15 signature"),
                &public_key,
                &self.msg,
                &signature,
            )?;
            for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th public key limb", i)),
                    limb.assigned_val(),
                    i,
                )?;
            }
            let num_limb_n = public_key.n.num_limbs();
            for (i, val) in hashed_msg.into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                    val,
                    num_limb_n + i,
                )?;
            }
            layouter.assign_region(
                || "assert is_valid==1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig4,
        TestRSASignatureWithHashCircuit4,
        test_rsa_signature_with_hash_circuit4,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config.rsa_config);
            let sha256_chip = self.sha256_chip(config.sha256_config);
            let bigint_chip = rsa_chip.bigint_chip();
            let main_gate = rsa_chip.main_gate();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys: invalid public key case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let hashed_msg = Sha256::digest(&self.msg);
                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let invalid_msg = [1; 32];
                    let mut sign = self
                        .private_key
                        .sign(padding, &invalid_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    Ok((public_key, sign))
                },
            )?;
            let mut verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
            let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                layouter.namespace(|| "verify pkcs1v15 signature"),
                &public_key,
                &self.msg,
                &signature,
            )?;
            for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th public key limb", i)),
                    limb.assigned_val(),
                    i,
                )?;
            }
            let num_limb_n = public_key.n.num_limbs();
            for (i, val) in hashed_msg.into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                    val,
                    num_limb_n + i,
                )?;
            }
            layouter.assign_region(
                || "assert is_valid==1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );
}
