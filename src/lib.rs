//! This library provides a RSA verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).
//!
//! A chip in this library, [`RSAChip`], defines constraints for verifying the RSA relations, specifically modular power `x^e mod n` and [pkcs1v15 signature](https://www.rfc-editor.org/rfc/rfc3447) verification.
//! Its circuit configuration differs depending on whether the exponent parameter `e` of the RSA public key is variable or fixed.
//! For example, since `e` is often fixed to `65537` in the case of pkcs1v15 signature verification, defining `e` as a fixed parameter [`RSAPubE::Fix`] can optimize the number of constraints.
//!
//! In addition to [`RSAChip`], this library also provides a high-level circuit implementation to verify pkcs1v15 signatures, [`RSASignatureVerifier`].  
//! The verification function in [`RSAChip`] requires as input a hashed message, whereas the function in [`RSASignatureVerifier`] computes a SHA256 hash of the given message and verifies the given signature for that hash.

pub mod big_integer;
mod chip;
mod instructions;
use big_integer::*;
pub use chip::*;
use halo2wrong::halo2::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::Error,
};
pub use instructions::*;
mod macros;
use halo2wrong::halo2::circuit::Layouter;
pub use macros::*;
//pub use zkevm_circuits::sha256_circuit::sha256_bit::{Sha256BitChip, Sha256BitConfig};
pub use halo2_dynamic_sha256;
use halo2_dynamic_sha256::{Field, Sha256BitConfig, Sha256DynamicChip, Sha256DynamicConfig};

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

use maingate::{
    big_to_fe, decompose_big, AssignedValue, MainGate, MainGateInstructions, RangeChip,
    RangeInstructions, RegionCtx,
};
use num_bigint::BigUint;

/// A parameter `e` in the RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub enum RSAPubE<F: FieldExt> {
    /// A variable parameter `e`.
    Var(UnassignedInteger<F>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// A parameter `e` in the assigned RSA public key.
#[derive(Clone, Debug)]
pub enum AssignedRSAPubE<F: FieldExt> {
    /// A variable parameter `e`.
    Var(AssignedInteger<F, Fresh>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSAPublicKey<F: FieldExt> {
    /// a modulus parameter
    pub n: UnassignedInteger<F>,
    /// an exponent parameter
    pub e: RSAPubE<F>,
}

impl<F: FieldExt> RSAPublicKey<F> {
    /// Creates new [`RSAPublicKey`] from `n` and `e`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    /// * e - a parameter `e`.
    ///
    /// # Return values
    /// Returns new [`RSAPublicKey`].
    pub fn new(n: UnassignedInteger<F>, e: RSAPubE<F>) -> Self {
        Self { n, e }
    }

    pub fn without_witness(num_limbs: usize, fix_e: BigUint) -> Self {
        let n = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        let e = RSAPubE::<F>::Fix(fix_e);
        Self { n, e }
    }
}

/// An assigned RSA public key.
#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<F: FieldExt> {
    /// a modulus parameter
    pub n: AssignedInteger<F, Fresh>,
    /// an exponent parameter
    pub e: AssignedRSAPubE<F>,
}

impl<F: FieldExt> AssignedRSAPublicKey<F> {
    /// Creates new [`AssignedRSAPublicKey`] from assigned `n` and `e`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    /// * e - an assigned parameter `e`.
    ///
    /// # Return values
    /// Returns new [`AssignedRSAPublicKey`].
    pub fn new(n: AssignedInteger<F, Fresh>, e: AssignedRSAPubE<F>) -> Self {
        Self { n, e }
    }
}

/// RSA signature that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSASignature<F: FieldExt> {
    c: UnassignedInteger<F>,
}

impl<F: FieldExt> RSASignature<F> {
    /// Creates new [`RSASignature`] from its integer.
    ///
    /// # Arguments
    /// * c - an integer of the signature.
    ///
    /// # Return values
    /// Returns new [`RSASignature`].
    pub fn new(c: UnassignedInteger<F>) -> Self {
        Self { c }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        let c = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        Self { c }
    }
}

/// An assigned RSA signature.
#[derive(Clone, Debug)]
pub struct AssignedRSASignature<F: FieldExt> {
    c: AssignedInteger<F, Fresh>,
}

impl<F: FieldExt> AssignedRSASignature<F> {
    /// Creates new [`AssignedRSASignature`] from its assigned integer.
    ///
    /// # Arguments
    /// * c - an assigned integer of the signature.
    ///
    /// # Return values
    /// Returns new [`AssignedRSASignature`].
    pub fn new(c: AssignedInteger<F, Fresh>) -> Self {
        Self { c }
    }
}

/// A circuit implementation to verify pkcs1v15 signatures.
#[derive(Clone, Debug)]
pub struct RSASignatureVerifier<F: Field> {
    rsa_chip: RSAChip<F>,
    sha256_chip: Sha256DynamicChip<F>,
}

impl<F: Field> RSASignatureVerifier<F> {
    /// Creates new [`RSASignatureVerifier`] from [`RSAChip`] and [`Sha256BitChip`].
    ///
    /// # Arguments
    /// * rsa_chip - a [`RSAChip`].
    /// * sha256_chip - a [`Sha256DynamicChip`]
    ///
    /// # Return values
    /// Returns new [`RSASignatureVerifier`].
    pub fn new(rsa_chip: RSAChip<F>, sha256_chip: Sha256DynamicChip<F>) -> Self {
        Self {
            rsa_chip,
            sha256_chip,
        }
    }

    /// Given a RSA public key, signed message bytes, and a pkcs1v15 signature, verifies the signature with SHA256 hash function.
    ///
    /// # Arguments
    /// * layouter - a layouter of the constraints system.
    /// * public_key - an assigned public key used for the verification.
    /// * msg - signed message bytes.
    /// * signature - a pkcs1v15 signature to be verified.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `signature` is valid for `public_key` and `msg`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    pub fn verify_pkcs1v15_signature(
        &self,
        mut layouter: impl Layouter<F>,
        public_key: &AssignedRSAPublicKey<F>,
        msg: &[u8],
        signature: &AssignedRSASignature<F>,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        let mut sha256 = self.sha256_chip.clone();
        let (_, _, mut hashed_bytes) = sha256.digest(layouter.namespace(|| "sha256"), msg)?;
        hashed_bytes.reverse();
        let bytes_len = hashed_bytes.len();
        let limb_bytes = RSAChip::<F>::LIMB_WIDTH / 8;
        let rsa_chip = self.rsa_chip.clone();
        let main_gate = rsa_chip.main_gate();

        let is_sign_valid = layouter.assign_region(
            || "sign verification",
            |mut region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut assigned_limbs = Vec::with_capacity(bytes_len / limb_bytes);
                let c256 = main_gate.assign_constant(ctx, F::from(256u64))?;
                for i in 0..(bytes_len / limb_bytes) {
                    let mut limb_val = main_gate.assign_constant(ctx, F::zero())?;
                    let mut coeff = main_gate.assign_constant(ctx, F::one())?;
                    for j in 0..limb_bytes {
                        // let coeff =
                        //     main_gate.assign_constant(ctx, big_to_fe(BigUint::from(1usize) << (8 * j)))?;
                        limb_val = main_gate.mul_add(
                            ctx,
                            &coeff,
                            &hashed_bytes[limb_bytes * i + j],
                            &limb_val,
                        )?;
                        coeff = main_gate.mul(ctx, &coeff, &c256)?;
                    }
                    assigned_limbs.push(AssignedLimb::from(limb_val));
                }
                let hashed_msg = AssignedInteger::new(&assigned_limbs);
                let is_sign_valid =
                    rsa_chip.verify_pkcs1v15_signature(ctx, public_key, &hashed_msg, signature)?;
                Ok(is_sign_valid)
            },
        )?;

        // 2. Verify `signature` with `public_key` and `hashed_bytes`.
        hashed_bytes.reverse();
        Ok((is_sign_valid, hashed_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_dynamic_sha256::{Field, Sha256DynamicChip, Sha256DynamicConfig};
    use halo2wrong::curves::bn256::Fr as BnFr;
    use halo2wrong::halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};
    use rsa::*;
    use sha2::{Digest, Sha256};
    use std::marker::PhantomData;

    macro_rules! impl_rsa_signature_test_circuit {
        ($config_name:ident, $circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $should_be_error:expr, $( $synth:tt )*) => {
            #[derive(Debug,Clone)]
            struct $config_name<F:Field> {
                rsa_config: RSAConfig,
                sha256_config: Sha256DynamicConfig<F>
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
                fn sha256_chip(&self, config: Sha256DynamicConfig<F>) -> Sha256DynamicChip<F> {
                    Sha256DynamicChip::new(config)
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
                    let (mut composition_bit_lens, mut overflow_bit_lens) =
                        RSAChip::<F>::compute_range_lens(
                            Self::BITS_LEN / Self::LIMB_WIDTH,
                        );
                    let (mut sha_composition_bit_lens, mut sha_overflow_bit_lens) = Sha256DynamicChip::<F>::compute_range_lens();
                    composition_bit_lens.append(&mut sha_composition_bit_lens);
                    overflow_bit_lens.append(&mut sha_overflow_bit_lens);
                    let range_config = RangeChip::<F>::configure(
                        meta,
                        &main_gate_config,
                        composition_bit_lens,
                        overflow_bit_lens,
                    );
                    let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
                    let rsa_config = RSAConfig::new(bigint_config);
                    let sha256_bit_config = Sha256BitConfig::configure(meta);
                    let sha256_config = Sha256DynamicConfig::new(main_gate_config.clone(),range_config.clone(),sha256_bit_config, 128+64);
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
                    if $should_be_error {
                        assert!(prover.verify().is_err());
                    } else {
                        assert_eq!(prover.verify(), Ok(()))
                    }
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
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
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
            let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);

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
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
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
            let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
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
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
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
            let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
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
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys: invalid private key case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
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
            let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
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
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestDeriveTraitsConfig,
        TestDeriveTraitsCircuit,
        test_derive_traits,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let config = config.clone();
            format!("{config:?}");
            let rsa_chip = self.rsa_chip(config.rsa_config);
            let sha256_chip = self.sha256_chip(config.sha256_config);
            let bigint_chip = rsa_chip.bigint_chip();
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys: invalid private key case",
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
                    let sign = RSASignature::new(sign_unassigned).clone();
                    format!("{sign:?}");
                    let sign = rsa_chip.assign_signature(ctx, sign)?.clone();
                    format!("{sign:?}");
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix).clone();
                    format!("{public_key:?}");
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?.clone();
                    format!("{public_key:?}");
                    Ok((public_key, sign))
                },
            )?;
            let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip).clone();
            format!("{verifier:?}");
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestUnimplementedConfig,
        TestUnimplemented,
        test_rsa_signature_with_hash_unimplemented,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            Ok(())
        }
    );
}
