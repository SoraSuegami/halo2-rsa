//! This library provides a RSA verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).
//!
//! A chip in this library, [`RSAChip`], defines constraints for verifying the RSA relations, specifically modular power `x^e mod n` and [pkcs1v15 signature](https://www.rfc-editor.org/rfc/rfc3447) verification.
//! Its circuit configuration differs depending on whether the exponent parameter `e` of the RSA public key is variable or fixed.
//! For example, since `e` is often fixed to `65537` in the case of pkcs1v15 signature verification, defining `e` as a fixed parameter [`RSAPubE::Fix`] can optimize the number of constraints.
//!
//! In addition to [`RSAChip`], this library also provides a high-level circuit implementation to verify pkcs1v15 signatures, [`RSASignatureVerifier`].  
//! The verification function in [`RSAChip`] requires as input a hashed message, whereas the function in [`RSASignatureVerifier`] computes a SHA256 hash of the given message and verifies the given signature for that hash.

pub mod big_uint;
use std::marker::PhantomData;

use big_uint::*;

use halo2_base::halo2_proofs::{circuit::Region, circuit::Value, plonk::Error};
use halo2_base::utils::fe_to_bigint;
use halo2_base::ContextParams;
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context,
};
use halo2_ecc::bigint::{
    big_is_equal, big_is_zero, big_less_than, carry_mod, mul_no_carry, negative, select, sub,
    CRTInteger, FixedCRTInteger, FixedOverflowInteger, OverflowInteger,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};

mod chip;
mod instructions;
pub use chip::*;
pub use instructions::*;
//mod macros;
//pub use macros::*;
//pub use zkevm_circuits::sha256_circuit::sha256_bit::{Sha256BitChip, Sha256BitConfig};
pub use halo2_dynamic_sha256;
use halo2_dynamic_sha256::{Field, Sha256BitConfig, Sha256DynamicConfig};

// #[cfg(target_arch = "wasm32")]
// mod wasm;
// #[cfg(target_arch = "wasm32")]
// pub use wasm::*;

/// A parameter `e` in the RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub enum RSAPubE {
    /// A variable parameter `e`.
    Var(Value<BigUint>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// A parameter `e` in the assigned RSA public key.
#[derive(Clone, Debug)]
pub enum AssignedRSAPubE<'v, F: PrimeField> {
    /// A variable parameter `e`.
    Var(AssignedValue<'v, F>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSAPublicKey<F: PrimeField> {
    /// a modulus parameter
    pub n: Value<BigUint>,
    /// an exponent parameter
    pub e: RSAPubE,
    _f: PhantomData<F>,
}

impl<F: PrimeField> RSAPublicKey<F> {
    /// Creates new [`RSAPublicKey`] from `n` and `e`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    /// * e - a parameter `e`.
    ///
    /// # Return values
    /// Returns new [`RSAPublicKey`].
    pub fn new(n: Value<BigUint>, e: RSAPubE) -> Self {
        Self {
            n,
            e,
            _f: PhantomData,
        }
    }

    pub fn without_witness(fix_e: BigUint) -> Self {
        let n = Value::unknown();
        let e = RSAPubE::Fix(fix_e);
        Self {
            n,
            e,
            _f: PhantomData,
        }
    }
}

/// An assigned RSA public key.
#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<'v, F: PrimeField> {
    /// a modulus parameter
    pub n: AssignedBigUint<'v, F, Fresh>,
    /// an exponent parameter
    pub e: AssignedRSAPubE<'v, F>,
}

impl<'v, F: PrimeField> AssignedRSAPublicKey<'v, F> {
    /// Creates new [`AssignedRSAPublicKey`] from assigned `n` and `e`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    /// * e - an assigned parameter `e`.
    ///
    /// # Return values
    /// Returns new [`AssignedRSAPublicKey`].
    pub fn new(n: AssignedBigUint<'v, F, Fresh>, e: AssignedRSAPubE<'v, F>) -> Self {
        Self { n, e }
    }
}

/// RSA signature that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSASignature<F: PrimeField> {
    c: Value<BigUint>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> RSASignature<F> {
    /// Creates new [`RSASignature`] from its integer.
    ///
    /// # Arguments
    /// * c - an integer of the signature.
    ///
    /// # Return values
    /// Returns new [`RSASignature`].
    pub fn new(c: Value<BigUint>) -> Self {
        Self { c, _f: PhantomData }
    }

    pub fn without_witness() -> Self {
        let c = Value::unknown();
        Self { c, _f: PhantomData }
    }
}

/// An assigned RSA signature.
#[derive(Clone, Debug)]
pub struct AssignedRSASignature<'v, F: PrimeField> {
    c: AssignedBigUint<'v, F, Fresh>,
}

impl<'v, F: PrimeField> AssignedRSASignature<'v, F> {
    /// Creates new [`AssignedRSASignature`] from its assigned integer.
    ///
    /// # Arguments
    /// * c - an assigned integer of the signature.
    ///
    /// # Return values
    /// Returns new [`AssignedRSASignature`].
    pub fn new(c: AssignedBigUint<'v, F, Fresh>) -> Self {
        Self { c }
    }
}

/// A circuit implementation to verify pkcs1v15 signatures.
#[derive(Clone, Debug)]
pub struct RSASignatureVerifier<F: Field> {
    rsa_config: RSAConfig<F>,
    sha256_config: Sha256DynamicConfig<F>,
}

impl<F: Field> RSASignatureVerifier<F> {
    /// Creates new [`RSASignatureVerifier`] from [`RSAChip`] and [`Sha256BitChip`].
    ///
    /// # Arguments
    /// * rsa_config - a [`RSAConfig`].
    /// * sha256_config - a [`Sha256DynamicConfig`]
    ///
    /// # Return values
    /// Returns new [`RSASignatureVerifier`].
    pub fn new(rsa_config: RSAConfig<F>, sha256_config: Sha256DynamicConfig<F>) -> Self {
        Self {
            rsa_config,
            sha256_config,
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
    pub fn verify_pkcs1v15_signature<'a, 'b: 'a>(
        &'a self,
        // mut layouter: impl Layouter<F>,
        ctx: &mut Context<'b, F>,
        public_key: &AssignedRSAPublicKey<'b, F>,
        msg: &'a [u8],
        signature: &AssignedRSASignature<'b, F>,
    ) -> Result<(AssignedValue<'b, F>, Vec<AssignedValue<'b, F>>), Error> {
        let sha256 = self.sha256_config.clone();
        let rsa = self.rsa_config.clone();
        let biguint = &rsa.biguint_config();
        let (_, _, mut hashed_bytes) = sha256.digest(ctx, msg)?;
        hashed_bytes.reverse();
        let bytes_bits = hashed_bytes.len() * 8;
        let limb_bits = biguint.limb_bits();
        let limb_bytes = limb_bits / 8;
        let mut hashed_u64s = vec![];
        let bases = (0..limb_bytes)
            .map(|i| F::from((1u64 << (8 * i)) as u64))
            .map(QuantumCell::Constant)
            .collect::<Vec<QuantumCell<F>>>();
        for i in 0..(bytes_bits / limb_bits) {
            let left = hashed_bytes[limb_bytes * i..limb_bytes * (i + 1)]
                .iter()
                .map(QuantumCell::Existing)
                .collect::<Vec<QuantumCell<F>>>();
            let sum = biguint.gate().inner_product(ctx, left, bases.clone());
            hashed_u64s.push(sum);
        }
        let is_sign_valid =
            rsa.verify_pkcs1v15_signature(ctx, public_key, &hashed_u64s, signature)?;

        // let is_sign_valid = layouter.assign_region(
        //     || "sign verification",
        //     |mut region| {
        //         let offset = 0;
        //         let ctx = &mut RegionCtx::new(region, offset);
        //         let mut assigned_limbs = Vec::with_capacity(bytes_len / limb_bytes);
        //         let c256 = main_gate.assign_constant(ctx, F::from(256u64))?;
        //         for i in 0..(bytes_len / limb_bytes) {
        //             let mut limb_val = main_gate.assign_constant(ctx, F::zero())?;
        //             let mut coeff = main_gate.assign_constant(ctx, F::one())?;
        //             for j in 0..limb_bytes {
        //                 // let coeff =
        //                 //     main_gate.assign_constant(ctx, big_to_fe(BigUint::from(1usize) << (8 * j)))?;
        //                 limb_val = main_gate.mul_add(
        //                     ctx,
        //                     &coeff,
        //                     &hashed_bytes[limb_bytes * i + j],
        //                     &limb_val,
        //                 )?;
        //                 coeff = main_gate.mul(ctx, &coeff, &c256)?;
        //             }
        //             assigned_limbs.push(AssignedLimb::from(limb_val));
        //         }
        //         let hashed_msg = AssignedInteger::new(&assigned_limbs);
        //         let is_sign_valid =
        //             rsa_chip.verify_pkcs1v15_signature(ctx, public_key, &hashed_msg, signature)?;
        //         Ok(is_sign_valid)
        //     },
        // )?;
        hashed_bytes.reverse();
        Ok((is_sign_valid, hashed_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::big_uint::decompose_biguint;
    use halo2_base::halo2_proofs::{
        circuit::{Cell, Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, Column, ConstraintSystem, Instance},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
    use halo2_dynamic_sha256::{Field, Sha256DynamicConfig};

    use num_bigint::RandomBits;
    use num_traits::FromPrimitive;
    use rand::{thread_rng, Rng};
    use rsa::{Hash, PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};

    macro_rules! impl_rsa_signature_test_circuit {
        ($config_name:ident, $circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $msg_len:expr, $k:expr, $should_be_error:expr, $( $synth:tt )*) => {
            #[derive(Debug,Clone)]
            struct $config_name<F:Field> {
                rsa_config: RSAConfig<F>,
                sha256_config: Sha256DynamicConfig<F>,
                n_instance: Column<Instance>,
                hash_instance: Column<Instance>
            }

            struct $circuit_name<F: Field> {
                private_key: RsaPrivateKey,
                public_key: RsaPublicKey,
                msg: Vec<u8>,
                _f: PhantomData<F>
            }

            impl<F: Field> $circuit_name<F> {
                const BITS_LEN:usize = $bits_len;
                const MSG_LEN:usize = $msg_len;
                const LIMB_WIDTH:usize = 64;
                const EXP_LIMB_BITS:usize = 5;
                const DEFAULT_E: u128 = 65537;
                const NUM_ADVICE:usize = 50;
                const NUM_FIXED:usize = 1;
                const NUM_LOOKUP_ADVICE:usize = 4;
                const LOOKUP_BITS:usize = 12;
            }

            impl<F: Field> Circuit<F> for $circuit_name<F> {
                type Config = $config_name<F>;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let range_config = RangeConfig::configure(meta,Vertical, &[Self::NUM_ADVICE], &[Self::NUM_LOOKUP_ADVICE], Self::NUM_FIXED, Self::LOOKUP_BITS, 0, $k);
                    let bigint_config = BigUintConfig::construct(range_config.clone(), 64);
                    let rsa_config = RSAConfig::construct(bigint_config, Self::BITS_LEN, Self::EXP_LIMB_BITS);
                    let sha256_bit_config = Sha256BitConfig::configure(meta);
                    let sha256_config = Sha256DynamicConfig::construct(sha256_bit_config, Self::MSG_LEN, range_config);
                    let n_instance = meta.instance_column();
                    let hash_instance = meta.instance_column();
                    meta.enable_equality(n_instance);
                    meta.enable_equality(hash_instance);
                    Self::Config {
                        rsa_config,
                        sha256_config,
                        n_instance,
                        hash_instance
                    }
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
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
                    let num_limbs = $bits_len / 64;
                    let limb_bits = 64;
                    let n_fes = decompose_biguint::<F>(&n, num_limbs, limb_bits);
                    let hash_fes = hashed_msg.iter().map(|byte| F::from(*byte as u64)).collect::<Vec<F>>();
                    // let mut column0_public_inputs = n_fes;
                    // column0_public_inputs.append(&mut hash_fes);
                    let public_inputs = vec![n_fes,hash_fes];
                    let k = $k;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    if $should_be_error {
                        assert!(prover.verify().is_err());
                    } else {
                        prover.verify().unwrap();
                    }
                }
                run::<Fr>();
            }
        };
    }

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig,
        TestRSASignatureWithHashCircuit,
        test_rsa_signature_with_hash_circuit,
        2048,
        1024,
        13,
        false,
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
            let (public_key_cells, hashed_msg_cells) = layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok((vec![], vec![]));
                    }

                    let mut aux = biguint_config.new_context(region);
                    let ctx = &mut aux;
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
                    let sign = config
                        .rsa_config
                        .assign_signature(ctx, RSASignature::new(Value::known(sign_big)))?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = config
                        .rsa_config
                        .assign_public_key(ctx, RSAPublicKey::new(Value::known(n_big), e_fix))?;
                    let verifier = RSASignatureVerifier::new(
                        config.rsa_config.clone(),
                        config.sha256_config.clone(),
                    );
                    let (is_valid, hashed_msg) =
                        verifier.verify_pkcs1v15_signature(ctx, &public_key, &self.msg, &sign)?;
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
                    Ok((public_key_cells, hashed_msg_cells))
                },
            )?;
            for (i, cell) in public_key_cells.into_iter().enumerate() {
                layouter.constrain_instance(cell, config.n_instance, i)?;
            }
            for (i, cell) in hashed_msg_cells.into_iter().enumerate() {
                layouter.constrain_instance(cell, config.hash_instance, i)?;
            }
            Ok(())
        }
    );

    // impl_rsa_signature_test_circuit!(
    //     TestRSASignatureWithHashConfig2,
    //     TestRSASignatureWithHashCircuit2,
    //     test_rsa_signature_with_hash_circuit2,
    //     1024,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let rsa_chip = self.rsa_chip(config.rsa_config);
    //         let sha256_chip = self.sha256_chip(config.sha256_config);
    //         let bigint_chip = rsa_chip.bigint_chip();
    //         let main_gate = rsa_chip.main_gate();
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         let limb_width = Self::LIMB_WIDTH;
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         let (public_key, signature) = layouter.assign_region(
    //             || "rsa signature with hash test using 1024 bits public keys",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let hashed_msg = Sha256::digest(&self.msg);
    //                 let padding = PaddingScheme::PKCS1v15Sign {
    //                     hash: Some(Hash::SHA2_256),
    //                 };
    //                 let mut sign = self
    //                     .private_key
    //                     .sign(padding, &hashed_msg)
    //                     .expect("fail to sign a hashed message.");
    //                 sign.reverse();
    //                 let sign_big = BigUint::from_bytes_le(&sign);
    //                 let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
    //                 let sign_unassigned = UnassignedInteger::from(sign_limbs);
    //                 let sign = RSASignature::new(sign_unassigned);
    //                 let sign = rsa_chip.assign_signature(ctx, sign)?;
    //                 let n_big =
    //                     BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
    //                         .unwrap();
    //                 let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
    //                 let public_key = RSAPublicKey::new(n_unassigned, e_fix);
    //                 let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
    //                 Ok((public_key, sign))
    //             },
    //         )?;
    //         let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
    //         let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
    //             layouter.namespace(|| "verify pkcs1v15 signature"),
    //             &public_key,
    //             &self.msg,
    //             &signature,
    //         )?;
    //         for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
    //             main_gate.expose_public(
    //                 layouter.namespace(|| format!("expose {} th public key limb", i)),
    //                 limb.assigned_val(),
    //                 i,
    //             )?;
    //         }
    //         let num_limb_n = public_key.n.num_limbs();
    //         for (i, val) in hashed_msg.into_iter().enumerate() {
    //             main_gate.expose_public(
    //                 layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
    //                 val,
    //                 num_limb_n + i,
    //             )?;
    //         }
    //         layouter.assign_region(
    //             || "assert is_valid==1",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 main_gate.assert_one(ctx, &is_valid)?;
    //                 Ok(())
    //             },
    //         )?;
    //         Ok(())
    //     }
    // );

    // impl_rsa_signature_test_circuit!(
    //     TestRSASignatureWithHashConfig3,
    //     TestRSASignatureWithHashCircuit3,
    //     test_rsa_signature_with_hash_circuit3,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let rsa_chip = self.rsa_chip(config.rsa_config);
    //         let sha256_chip = self.sha256_chip(config.sha256_config);
    //         let bigint_chip = rsa_chip.bigint_chip();
    //         let main_gate = rsa_chip.main_gate();
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         let limb_width = Self::LIMB_WIDTH;
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         let (public_key, signature) = layouter.assign_region(
    //             || "rsa signature with hash test using 2048 bits public keys: invalid signed message case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let hashed_msg = Sha256::digest(&self.msg);
    //                 let padding = PaddingScheme::PKCS1v15Sign {
    //                     hash: Some(Hash::SHA2_256),
    //                 };
    //                 let mut rng = thread_rng();
    //                 let invalid_private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    //                 let mut sign = invalid_private_key
    //                     .sign(padding, &hashed_msg)
    //                     .expect("fail to sign a hashed message.");
    //                 sign.reverse();
    //                 let sign_big = BigUint::from_bytes_le(&sign);
    //                 let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
    //                 let sign_unassigned = UnassignedInteger::from(sign_limbs);
    //                 let sign = RSASignature::new(sign_unassigned);
    //                 let sign = rsa_chip.assign_signature(ctx, sign)?;
    //                 let n_big =
    //                     BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
    //                         .unwrap();
    //                 let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
    //                 let public_key = RSAPublicKey::new(n_unassigned, e_fix);
    //                 let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
    //                 Ok((public_key, sign))
    //             },
    //         )?;
    //         let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
    //         let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
    //             layouter.namespace(|| "verify pkcs1v15 signature"),
    //             &public_key,
    //             &self.msg,
    //             &signature,
    //         )?;
    //         for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
    //             main_gate.expose_public(
    //                 layouter.namespace(|| format!("expose {} th public key limb", i)),
    //                 limb.assigned_val(),
    //                 i,
    //             )?;
    //         }
    //         let num_limb_n = public_key.n.num_limbs();
    //         for (i, val) in hashed_msg.into_iter().enumerate() {
    //             main_gate.expose_public(
    //                 layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
    //                 val,
    //                 num_limb_n + i,
    //             )?;
    //         }
    //         layouter.assign_region(
    //             || "assert is_valid==1",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 main_gate.assert_one(ctx, &is_valid)?;
    //                 Ok(())
    //             },
    //         )?;
    //         Ok(())
    //     }
    // );

    // impl_rsa_signature_test_circuit!(
    //     TestRSASignatureWithHashConfig4,
    //     TestRSASignatureWithHashCircuit4,
    //     test_rsa_signature_with_hash_circuit4,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let rsa_chip = self.rsa_chip(config.rsa_config);
    //         let sha256_chip = self.sha256_chip(config.sha256_config);
    //         let bigint_chip = rsa_chip.bigint_chip();
    //         let main_gate = rsa_chip.main_gate();
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         let limb_width = Self::LIMB_WIDTH;
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         let (public_key, signature) = layouter.assign_region(
    //             || "rsa signature with hash test using 2048 bits public keys: invalid private key case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let padding = PaddingScheme::PKCS1v15Sign {
    //                     hash: Some(Hash::SHA2_256),
    //                 };
    //                 let invalid_msg = [1; 32];
    //                 let mut sign = self
    //                     .private_key
    //                     .sign(padding, &invalid_msg)
    //                     .expect("fail to sign a hashed message.");
    //                 sign.reverse();
    //                 let sign_big = BigUint::from_bytes_le(&sign);
    //                 let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
    //                 let sign_unassigned = UnassignedInteger::from(sign_limbs);
    //                 let sign = RSASignature::new(sign_unassigned);
    //                 let sign = rsa_chip.assign_signature(ctx, sign)?;
    //                 let n_big =
    //                     BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
    //                         .unwrap();
    //                 let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
    //                 let public_key = RSAPublicKey::new(n_unassigned, e_fix);
    //                 let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
    //                 Ok((public_key, sign))
    //             },
    //         )?;
    //         let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
    //         let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
    //             layouter.namespace(|| "verify pkcs1v15 signature"),
    //             &public_key,
    //             &self.msg,
    //             &signature,
    //         )?;
    //         for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
    //             main_gate.expose_public(
    //                 layouter.namespace(|| format!("expose {} th public key limb", i)),
    //                 limb.assigned_val(),
    //                 i,
    //             )?;
    //         }
    //         let num_limb_n = public_key.n.num_limbs();
    //         for (i, val) in hashed_msg.into_iter().enumerate() {
    //             main_gate.expose_public(
    //                 layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
    //                 val,
    //                 num_limb_n + i,
    //             )?;
    //         }
    //         layouter.assign_region(
    //             || "assert is_valid==1",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 main_gate.assert_one(ctx, &is_valid)?;
    //                 Ok(())
    //             },
    //         )?;
    //         Ok(())
    //     }
    // );

    // impl_rsa_signature_test_circuit!(
    //     TestDeriveTraitsConfig,
    //     TestDeriveTraitsCircuit,
    //     test_derive_traits,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let config = config.clone();
    //         format!("{config:?}");
    //         let rsa_chip = self.rsa_chip(config.rsa_config);
    //         let sha256_chip = self.sha256_chip(config.sha256_config);
    //         let bigint_chip = rsa_chip.bigint_chip();
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         let limb_width = Self::LIMB_WIDTH;
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "rsa signature with hash test using 2048 bits public keys: invalid private key case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let hashed_msg = Sha256::digest(&self.msg);
    //                 let padding = PaddingScheme::PKCS1v15Sign {
    //                     hash: Some(Hash::SHA2_256),
    //                 };
    //                 let mut sign = self
    //                     .private_key
    //                     .sign(padding, &hashed_msg)
    //                     .expect("fail to sign a hashed message.");
    //                 sign.reverse();
    //                 let sign_big = BigUint::from_bytes_le(&sign);
    //                 let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
    //                 let sign_unassigned = UnassignedInteger::from(sign_limbs);
    //                 let sign = RSASignature::new(sign_unassigned).clone();
    //                 format!("{sign:?}");
    //                 let sign = rsa_chip.assign_signature(ctx, sign)?.clone();
    //                 format!("{sign:?}");
    //                 let n_big =
    //                     BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
    //                         .unwrap();
    //                 let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
    //                 let public_key = RSAPublicKey::new(n_unassigned, e_fix).clone();
    //                 format!("{public_key:?}");
    //                 let public_key = rsa_chip.assign_public_key(ctx, public_key)?.clone();
    //                 format!("{public_key:?}");
    //                 Ok((public_key, sign))
    //             },
    //         )?;
    //         let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip).clone();
    //         format!("{verifier:?}");
    //         Ok(())
    //     }
    // );

    // impl_rsa_signature_test_circuit!(
    //     TestUnimplementedConfig,
    //     TestUnimplemented,
    //     test_rsa_signature_with_hash_unimplemented,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         Ok(())
    //     }
    // );
}
