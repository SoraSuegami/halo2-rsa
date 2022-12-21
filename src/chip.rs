use crate::big_integer::{
    AssignedInteger, AssignedLimb, BigIntChip, BigIntConfig, BigIntInstructions,
};
use crate::{
    AssignedRSAPubE, AssignedRSAPublicKey, AssignedRSASignature, Fresh, Muled, RSAInstructions,
    RSAPubE, RSAPublicKey, RSASignature, RangeType, RefreshAux, UnassignedInteger,
};
use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value, plonk::Error};
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateInstructions, RangeChip,
    RangeConfig, RangeInstructions, RegionCtx,
};

use num_bigint::BigUint;
use std::marker::PhantomData;

/// Configuration for [`BigIntChip`].
#[derive(Clone, Debug)]
pub struct RSAConfig {
    /// Configuration for [`BigIntChip`].
    bigint_config: BigIntConfig,
}

impl RSAConfig {
    /// Creates new [`RSAConfig`] from [`BigIntConfig`].
    ///
    /// # Arguments
    /// * bigint_config - a configuration for [`BigIntChip`].
    ///
    /// # Return values
    /// Returns new [`RSAConfig`].
    pub fn new(bigint_config: BigIntConfig) -> Self {
        Self { bigint_config }
    }
}

/// Chip for [`RSAInstructions`].
#[derive(Debug, Clone)]
pub struct RSAChip<F: FieldExt> {
    /// Chip configuration.
    config: RSAConfig,
    /// The default bit length of [`Fresh`] type integers in this chip.
    bits_len: usize,
    /// The width of each limb when the exponent is decomposed.
    exp_limb_bits: usize,
    _f: PhantomData<F>,
}

impl<F: FieldExt> RSAInstructions<F> for RSAChip<F> {
    /// Assigns a [`AssignedRSAPublicKey`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - a RSA public key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedRSAPublicKey`].
    fn assign_public_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_key: RSAPublicKey<F>,
    ) -> Result<AssignedRSAPublicKey<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let n = bigint_chip.assign_integer(ctx, public_key.n)?;
        let e = match public_key.e {
            RSAPubE::Var(e) => AssignedRSAPubE::Var(bigint_chip.assign_integer(ctx, e)?),
            RSAPubE::Fix(e) => AssignedRSAPubE::Fix(e),
        };
        Ok(AssignedRSAPublicKey::new(n, e))
    }

    /// Assigns a [`AssignedRSASignature`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `signature` - a RSA signature to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedRSASignature`].
    fn assign_signature(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let c = bigint_chip.assign_integer(ctx, signature.c)?;
        Ok(AssignedRSASignature::new(c))
    }

    /// Given a base `x`, a RSA public key (e,n), performs the modular power `x^e mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `x` - a base integer.
    /// * `public_key` - an assigned RSA public key.
    ///
    /// # Return values
    /// Returns the modular power result `x^e mod n` as [`AssignedInteger<F, Fresh>`].
    fn modpow_public_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &AssignedInteger<F, Fresh>,
        public_key: &AssignedRSAPublicKey<F>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let bigint_chip = self.bigint_chip();
        bigint_chip.assert_in_field(ctx, x, &public_key.n)?;
        let powed = match &public_key.e {
            AssignedRSAPubE::Var(e) => {
                bigint_chip.pow_mod(ctx, x, e, &public_key.n, self.exp_limb_bits)
            }
            AssignedRSAPubE::Fix(e) => bigint_chip.pow_mod_fixed_exp(ctx, x, e, &public_key.n),
        }?;
        Ok(powed)
    }

    /// Given a RSA public key, a message hashed with SHA256, and a pkcs1v15 signature, verifies the signature with the public key and the hashed messaged.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - an assigned RSA public key.
    /// * `hashed_msg` - an assigned integer of the message hashed with SHA256.
    /// * `signature` - an assigned pkcs1v15 signature.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `signature` is valid for `public_key` and `hashed_msg`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn verify_pkcs1v15_signature(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_key: &AssignedRSAPublicKey<F>,
        hashed_msg: &AssignedInteger<F, Fresh>,
        signature: &AssignedRSASignature<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        let mut is_eq = main_gate.assign_constant(ctx, F::one())?;
        let powed = self.modpow_public_key(ctx, &signature.c, public_key)?;
        let hash_len = 4;
        // 1. Check hashed data
        // 64 * 4 = 256 bit, that is the first 4 numbers.
        for i in 0..hash_len {
            let is_hash_eq = main_gate.is_equal(ctx, &powed.limb(i), &hashed_msg.limb(i))?;
            is_eq = main_gate.and(ctx, &is_eq, &is_hash_eq)?;
        }

        // 2. Check hash prefix and 1 byte 0x00
        // sha256/152 bit
        // 0b00110000001100010011000000001101000001100000100101100000100001100100100000000001011001010000001100000100000000100000000100000101000000000000010000100000
        let prefix_64_1 =
            main_gate.assign_constant(ctx, big_to_fe(BigUint::from(217300885422736416u64)))?;
        let prefix_64_2 =
            main_gate.assign_constant(ctx, big_to_fe(BigUint::from(938447882527703397u64)))?;
        let is_prefix_64_1_eq = main_gate.is_equal(ctx, &powed.limb(hash_len), &prefix_64_1)?;
        let is_prefix_64_2_eq = main_gate.is_equal(ctx, &powed.limb(hash_len + 1), &prefix_64_2)?;
        is_eq = main_gate.and(ctx, &is_eq, &is_prefix_64_1_eq)?;
        is_eq = main_gate.and(ctx, &is_eq, &is_prefix_64_2_eq)?;
        // remain 24 bit
        let u32_v: BigUint = BigUint::from(1usize) << 32;
        let (remain_low, remain_high) = powed
            .limb(hash_len + 2)
            .value()
            .map(|v| {
                let big_v = fe_to_big(*v);
                let low = big_to_fe::<F>(&big_v % &u32_v);
                let high = big_to_fe::<F>(&big_v / &u32_v);
                (low, high)
            })
            .unzip();
        let range_chip = self.range_chip();
        let remain_low = range_chip.assign(ctx, remain_low, 4, 32)?;
        let remain_high = range_chip.assign(ctx, remain_high, 4, 32)?;
        let u32_assign = main_gate.assign_constant(ctx, big_to_fe(u32_v))?;
        let remain_concat = main_gate.mul_add(ctx, &remain_high, &u32_assign, &remain_low)?;
        main_gate.assert_equal(ctx, &powed.limb(hash_len + 2), &remain_concat)?;
        let prefix_32 = main_gate.assign_constant(ctx, big_to_fe(BigUint::from(3158320u32)))?;
        let is_prefix_32_eq = main_gate.is_equal(ctx, &remain_low, &prefix_32)?;
        is_eq = main_gate.and(ctx, &is_eq, &is_prefix_32_eq)?;

        // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
        let ff_32 = main_gate.assign_constant(ctx, big_to_fe(BigUint::from(4294967295u32)))?;
        let is_ff_32_eq = main_gate.is_equal(ctx, &remain_high, &ff_32)?;
        is_eq = main_gate.and(ctx, &is_eq, &is_ff_32_eq)?;
        let ff_64 =
            main_gate.assign_constant(ctx, big_to_fe(BigUint::from(18446744073709551615u64)))?;
        for i in (hash_len + 3)..(self.bits_len / Self::LIMB_WIDTH - 1) {
            let is_ff_64_eq = main_gate.is_equal(ctx, &powed.limb(i), &ff_64)?;
            is_eq = main_gate.and(ctx, &is_eq, &is_ff_64_eq)?;
        }
        //562949953421311 = 0b1111111111111111111111111111111111111111111111111 = 0x00 || 0x01 || (0xff)^*
        let last_em =
            main_gate.assign_constant(ctx, big_to_fe(BigUint::from(562949953421311u64)))?;
        let is_last_em_eq = main_gate.is_equal(
            ctx,
            &powed.limb(self.bits_len / Self::LIMB_WIDTH - 1),
            &last_em,
        )?;
        is_eq = main_gate.and(ctx, &is_eq, &is_last_em_eq)?;
        Ok(is_eq)
    }
}

impl<F: FieldExt> RSAChip<F> {
    pub const LIMB_WIDTH: usize = 64;

    /// Create a new [`RSAChip`] from the configuration and parameters.
    ///
    /// # Arguments
    /// * config - a configuration for [`RSAChip`].
    /// * bits_len - the default bit length of [`Fresh`] type integers in this chip.
    /// * exp_limb_bits - the width of each limb when the exponent is decomposed.
    ///
    /// # Return values
    /// Returns a new [`RSAChip`]
    pub fn new(config: RSAConfig, bits_len: usize, exp_limb_bits: usize) -> Self {
        RSAChip {
            config,
            bits_len,
            exp_limb_bits,
            _f: PhantomData,
        }
    }

    /// Getter for [`BigIntChip`].
    pub fn bigint_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_config.clone(),
            Self::LIMB_WIDTH,
            self.bits_len,
        )
    }

    /// Getter for [`RangeChip`].
    pub fn range_chip(&self) -> RangeChip<F> {
        self.bigint_chip().range_chip()
    }

    /// Getter for [`MainGate`].
    pub fn main_gate(&self) -> MainGate<F> {
        self.bigint_chip().main_gate()
    }

    /// Returns the bit length parameters necessary to configure the [`RangeChip`].
    ///
    /// # Arguments
    /// * num_limbs - the default number of limbs of [`Fresh`] integers.
    ///
    /// # Return values
    /// Returns a vector of composition bit lengthes (`composition_bit_lens`) and a vector of overflow bit lengthes (`overflow_bit_lens`), which are necessary for [`RangeConfig`].
    pub fn compute_range_lens(num_limbs: usize) -> (Vec<usize>, Vec<usize>) {
        let (mut composition_bit_lens, overflow_bit_lens) =
            BigIntChip::<F>::compute_range_lens(Self::LIMB_WIDTH, num_limbs);
        composition_bit_lens.push(32 / BigIntChip::<F>::NUM_LOOKUP_LIMBS);
        (composition_bit_lens, overflow_bit_lens)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use halo2wrong::halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };

    use halo2wrong::halo2::dev::MockProver;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};

    macro_rules! impl_rsa_modpow_test_circuit {
        ($circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $should_be_error:expr, $( $synth:tt )*) => {
            struct $circuit_name<F: FieldExt> {
                n: BigUint,
                e: BigUint,
                x: BigUint,
                _f: PhantomData<F>
            }

            impl<F: FieldExt> $circuit_name<F> {
                const BITS_LEN:usize = $bits_len;
                const LIMB_WIDTH:usize = RSAChip::<F>::LIMB_WIDTH;
                const EXP_LIMB_BITS:usize = 5;
                const DEFAULT_E: u128 = 65537;
                fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
                    RSAChip::new(config, Self::BITS_LEN,Self::EXP_LIMB_BITS)
                }
            }

            impl<F: FieldExt> Circuit<F> for $circuit_name<F> {
                type Config = RSAConfig;
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
                    RSAConfig::new(bigint_config)
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                fn run<F: FieldExt>() {
                    let mut rng = thread_rng();
                    let bits_len = $circuit_name::<F>::BITS_LEN as u64;
                    let mut n = BigUint::default();
                    while n.bits() != bits_len {
                        n = rng.sample(RandomBits::new(bits_len));
                    }
                    let e = rng.sample::<BigUint, _>(RandomBits::new($circuit_name::<F>::EXP_LIMB_BITS as u64)) % &n;
                    let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                    let circuit = $circuit_name::<F> {
                        n,
                        e,
                        x,
                        _f: PhantomData
                    };

                    let public_inputs = vec![vec![]];
                    let k = 17;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }

                use halo2wrong::curves::bn256::Fq as BnFq;
                use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
                run::<BnFq>();
                run::<PastaFp>();
                run::<PastaFq>();
            }
        };
    }

    use crate::big_pow_mod;

    impl_rsa_modpow_test_circuit!(
        TestRSAModPow2048Circuit,
        test_rsa_modpow_2048_circuit,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config);
            let bigint_chip = rsa_chip.bigint_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let e_limbs = decompose_big::<F>(self.e.clone(), 1, Self::EXP_LIMB_BITS);
                    let e_unassigned = UnassignedInteger::from(e_limbs);
                    let e_var = RSAPubE::Var(e_unassigned);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let public_key_var = RSAPublicKey::new(n_unassigned.clone(), e_var);
                    let public_key_var = rsa_chip.assign_public_key(ctx, public_key_var)?;
                    let public_key_fix = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key_fix = rsa_chip.assign_public_key(ctx, public_key_fix)?;
                    let x_limbs = decompose_big::<F>(self.x.clone(), num_limbs, limb_width);
                    let x_unassigned = UnassignedInteger::from(x_limbs);
                    let x_assigned = bigint_chip.assign_integer(ctx, x_unassigned)?;
                    let powed_var =
                        rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                    let powed_fix =
                        rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;
                    let valid_powed_var = big_pow_mod(&self.x, &self.e, &self.n);
                    let valid_powed_fix =
                        big_pow_mod(&self.x, &BigUint::from(Self::DEFAULT_E), &self.n);
                    let valid_powed_var =
                        bigint_chip.assign_constant_fresh(ctx, valid_powed_var)?;
                    let valid_powed_fix =
                        bigint_chip.assign_constant_fresh(ctx, valid_powed_fix)?;
                    bigint_chip.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;
                    bigint_chip.assert_equal_fresh(ctx, &powed_fix, &valid_powed_fix)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_modpow_test_circuit!(
        TestBadRSAModPow2048Circuit,
        test_bad_rsa_modpow_2048_circuit,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config);
            let bigint_chip = rsa_chip.bigint_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random rsa modpow test using 2048 bits public keys with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let e_limbs = decompose_big::<F>(self.e.clone(), 1, Self::EXP_LIMB_BITS);
                    let e_unassigned = UnassignedInteger::from(e_limbs);
                    let e_var = RSAPubE::Var(e_unassigned);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let public_key_var = RSAPublicKey::new(n_unassigned.clone(), e_var);
                    let public_key_var = rsa_chip.assign_public_key(ctx, public_key_var)?;
                    let public_key_fix = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key_fix = rsa_chip.assign_public_key(ctx, public_key_fix)?;
                    let x_limbs = decompose_big::<F>(self.x.clone(), num_limbs, limb_width);
                    let x_unassigned = UnassignedInteger::from(x_limbs);
                    let x_assigned = bigint_chip.assign_integer(ctx, x_unassigned)?;
                    let powed_var =
                        rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                    let powed_fix =
                        rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;
                    let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
                    bigint_chip.assert_equal_fresh(ctx, &powed_var, &zero)?;
                    bigint_chip.assert_equal_fresh(ctx, &powed_fix, &zero)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_modpow_test_circuit!(
        TestRSAModPow1024Circuit,
        test_rsa_modpow_1024_circuit,
        1024,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config);
            let bigint_chip = rsa_chip.bigint_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let e_limbs = decompose_big::<F>(self.e.clone(), 1, Self::EXP_LIMB_BITS);
                    let e_unassigned = UnassignedInteger::from(e_limbs);
                    let e_var = RSAPubE::Var(e_unassigned);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let public_key_var = RSAPublicKey::new(n_unassigned.clone(), e_var);
                    let public_key_var = rsa_chip.assign_public_key(ctx, public_key_var)?;
                    let public_key_fix = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key_fix = rsa_chip.assign_public_key(ctx, public_key_fix)?;
                    let x_limbs = decompose_big::<F>(self.x.clone(), num_limbs, limb_width);
                    let x_unassigned = UnassignedInteger::from(x_limbs);
                    let x_assigned = bigint_chip.assign_integer(ctx, x_unassigned)?;
                    let powed_var =
                        rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                    let powed_fix =
                        rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;
                    let valid_powed_var = big_pow_mod(&self.x, &self.e, &self.n);
                    let valid_powed_fix =
                        big_pow_mod(&self.x, &BigUint::from(Self::DEFAULT_E), &self.n);
                    let valid_powed_var =
                        bigint_chip.assign_constant_fresh(ctx, valid_powed_var)?;
                    let valid_powed_fix =
                        bigint_chip.assign_constant_fresh(ctx, valid_powed_fix)?;
                    bigint_chip.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;
                    bigint_chip.assert_equal_fresh(ctx, &powed_fix, &valid_powed_fix)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_modpow_test_circuit!(
        TestBadRSAModPow1024Circuit,
        test_bad_rsa_modpow_1024_circuit,
        1024,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config);
            let bigint_chip = rsa_chip.bigint_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random rsa modpow test using 2048 bits public keys with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let e_limbs = decompose_big::<F>(self.e.clone(), 1, Self::EXP_LIMB_BITS);
                    let e_unassigned = UnassignedInteger::from(e_limbs);
                    let e_var = RSAPubE::Var(e_unassigned);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let public_key_var = RSAPublicKey::new(n_unassigned.clone(), e_var);
                    let public_key_var = rsa_chip.assign_public_key(ctx, public_key_var)?;
                    let public_key_fix = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key_fix = rsa_chip.assign_public_key(ctx, public_key_fix)?;
                    let x_limbs = decompose_big::<F>(self.x.clone(), num_limbs, limb_width);
                    let x_unassigned = UnassignedInteger::from(x_limbs);
                    let x_assigned = bigint_chip.assign_integer(ctx, x_unassigned)?;
                    let powed_var =
                        rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                    let powed_fix =
                        rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;
                    let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
                    bigint_chip.assert_equal_fresh(ctx, &powed_var, &zero)?;
                    bigint_chip.assert_equal_fresh(ctx, &powed_fix, &zero)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_modpow_test_circuit!(
        TestDeriveTraitsCircuit,
        test_derive_traits,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config).clone();
            format!("{rsa_chip:?}");
            Ok(())
        }
    );

    impl_rsa_modpow_test_circuit!(
        TestUnimplemented1,
        test_rsa_signature_with_hash_unimplemented1,
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

    #[test]
    #[should_panic]
    fn test_unimplemented1() {
        use halo2wrong::curves::bn256::Fq as F;
        let mut rng = thread_rng();
        let bits_len = TestUnimplemented1::<F>::BITS_LEN as u64;
        let mut n = BigUint::default();
        while n.bits() != bits_len {
            n = rng.sample(RandomBits::new(bits_len));
        }
        let e = rng.sample::<BigUint, _>(RandomBits::new(
            TestUnimplemented1::<F>::EXP_LIMB_BITS as u64,
        )) % &n;
        let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
        let circuit = TestUnimplemented1::<F> {
            n,
            e,
            x,
            _f: PhantomData,
        };
        circuit.without_witnesses();
    }

    macro_rules! impl_rsa_signature_test_circuit {
        ($circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $should_be_error:expr, $( $synth:tt )*) => {
            struct $circuit_name<F: FieldExt> {
                _f: PhantomData<F>
            }

            impl<F: FieldExt> $circuit_name<F> {
                const BITS_LEN:usize = $bits_len;
                const LIMB_WIDTH:usize = RSAChip::<F>::LIMB_WIDTH;
                const EXP_LIMB_BITS:usize = 5;
                const DEFAULT_E: u128 = 65537;
                fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
                    RSAChip::new(config, Self::BITS_LEN,Self::EXP_LIMB_BITS)
                }
            }

            impl<F: FieldExt> Circuit<F> for $circuit_name<F> {
                type Config = RSAConfig;
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
                    RSAConfig::new(bigint_config)
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                use halo2wrong::halo2::dev::MockProver;
                fn run<F: FieldExt>() {
                    let circuit = $circuit_name::<F> {
                        _f: PhantomData
                    };

                    let public_inputs = vec![vec![]];
                    let k = 17;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }

                use halo2wrong::curves::bn256::Fq as BnFq;
                use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
                run::<BnFq>();
                run::<PastaFp>();
                run::<PastaFq>();
            }
        };
    }

    impl_rsa_signature_test_circuit!(
        TestRSASignatureCircuit1,
        test_rsa_signature_circuit1,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config);
            let bigint_chip = rsa_chip.bigint_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "rsa signature test using 2048 bits public keys with a correct case 1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_big = BigUint::from_str("27333278531038650284292446400685983964543820405055158402397263907659995327446166369388984969315774410223081038389734916442552953312548988147687296936649645550823280957757266695625382122565413076484125874545818286099364801140117875853249691189224238587206753225612046406534868213180954324992542640955526040556053150097561640564120642863954208763490114707326811013163227280580130702236406906684353048490731840275232065153721031968704703853746667518350717957685569289022049487955447803273805415754478723962939325870164033644600353029240991739641247820015852898600430315191986948597672794286676575642204004244219381500407").unwrap();
                    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    let sign_big = BigUint::from_str("27166015521685750287064830171899789431519297967327068200526003963687696216659347317736779094212876326032375924944649760206771585778103092909024744594654706678288864890801000499430246054971129440518072676833029702477408973737931913964693831642228421821166326489172152903376352031367604507095742732994611253344812562891520292463788291973539285729019102238815435155266782647328690908245946607690372534644849495733662205697837732960032720813567898672483741410294744324300408404611458008868294953357660121510817012895745326996024006347446775298357303082471522757091056219893320485806442481065207020262668955919408138704593").unwrap();
                    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let hashed_msg_big = BigUint::from_str("83814198383102558219731078260892729932246618004265700685467928187377105751529").unwrap();
                    let hashed_msg_limbs = decompose_big::<F>(hashed_msg_big.clone(), 4, limb_width);
                    let hashed_msg_unassigned = UnassignedInteger::from(hashed_msg_limbs);
                    let hashed_msg_assigned = bigint_chip.assign_integer(ctx, hashed_msg_unassigned)?;
                    let is_valid = rsa_chip.verify_pkcs1v15_signature(ctx, &public_key, &hashed_msg_assigned, &sign)?;
                    rsa_chip.main_gate().assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestRSASignatureCircuit2,
        test_rsa_signature_circuit2,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config);
            let bigint_chip = rsa_chip.bigint_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "rsa signature test using 2048 bits public keys with a correct case 2",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_big = BigUint::from_str("24226501697440012621102249466312043787685293040734225606346036389705515508545746221669035424138747582133889500686654172873671086178893587422987328751464627501601101326475761646014534358699943642495332701081302954020983110372109611581202820849485662540890985814355975252780310958088652613376767040069489530039075302709233494829280591680666351811024913107949144932224439129715181798714328219977771472462901856297952813239115577652450722815852332547886777292613005505949100406231716599634852632308325816916535875123863510650526931916871614411907700873376659841257216885666098127478325534982891697988739616416855214839339").unwrap();
                    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    let sign_big = BigUint::from_str("18928545496959757512579438348223103860103247450097569223971486743312798156950374943336714741350742176674694049986481729075548718599712271054643150030165230392897481507710187505775911256946250999396358633095137650326818007610162375520522758780751710735664264200260854016867498935206556916247099180950775474524799944404833222133011134000549939512938205188018503377612813102061504146765520561811620128786062447005833886367575841545493555268747671930923697279690399480501746857825917608323993022396398648205737336204493624060285359455268389160802763426461171262704764369336704988874821898000892148693988241020931055723252").unwrap();
                    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let hashed_msg_big = BigUint::from_str("83814198383102558219731078260892729932246618004265700685467928187377105751529").unwrap();
                    let hashed_msg_limbs = decompose_big::<F>(hashed_msg_big.clone(), 4, limb_width);
                    let hashed_msg_unassigned = UnassignedInteger::from(hashed_msg_limbs);
                    let hashed_msg_assigned = bigint_chip.assign_integer(ctx, hashed_msg_unassigned)?;
                    let is_valid = rsa_chip.verify_pkcs1v15_signature(ctx, &public_key, &hashed_msg_assigned, &sign)?;
                    rsa_chip.main_gate().assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestBadRSASignatureCircuit,
        test_bad_rsa_signature_circuit2,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config);
            let bigint_chip = rsa_chip.bigint_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "rsa signature test using 2048 bits public keys with a uncorrect case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_big = BigUint::from_str("24226501697440012621102249466312043787685293040734225606346036389705515508545746221669035424138747582133889500686654172873671086178893587422987328751464627501601101326475761646014534358699943642495332701081302954020983110372109611581202820849485662540890985814355975252780310958088652613376767040069489530039075302709233494829280591680666351811024913107949144932224439129715181798714328219977771472462901856297952813239115577652450722815852332547886777292613005505949100406231716599634852632308325816916535875123863510650526931916871614411907700873376659841257216885666098127478325534982891697988739616416855214839339").unwrap();
                    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    let sign_big = BigUint::from_str("18928545496959756512579438348223103860103247450097569223971486743312798156950374943336714741350742176674694049986481729075548718599712271054643150030165230392897481507710187505775911256946250999396358633095137650326818007610162375520522758780751710735664264200260854016867498935206556916247099180950775474524799944404833222133011134000549939512938205188018503377612813102061504146765520561811620128786062447005833886367575841545493555268747671930923697279690399480501746857825917608323993022396398648205737336204493624060285359455268389160802763426461171262704764369336704988874821898000892148693988241020931055723252").unwrap();
                    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let hashed_msg_big = BigUint::from_str("83814198383102558219731078260892729932246618004265700685467928187377105751529").unwrap();
                    let hashed_msg_limbs = decompose_big::<F>(hashed_msg_big.clone(), 4, limb_width);
                    let hashed_msg_unassigned = UnassignedInteger::from(hashed_msg_limbs);
                    let hashed_msg_assigned = bigint_chip.assign_integer(ctx, hashed_msg_unassigned)?;
                    let is_valid = rsa_chip.verify_pkcs1v15_signature(ctx, &public_key, &hashed_msg_assigned, &sign)?;
                    rsa_chip.main_gate().assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestUnimplemented2,
        test_rsa_signature_circuit_unimplemented,
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

    #[test]
    #[should_panic]
    fn test_unimplemented2() {
        use halo2wrong::curves::bn256::Fq as F;
        let circuit = TestUnimplemented2::<F> { _f: PhantomData };
        circuit.without_witnesses();
    }
}
