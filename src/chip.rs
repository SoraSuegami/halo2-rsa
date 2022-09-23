use crate::big_integer::{
    AssignedInteger, AssignedLimb, BigIntChip, BigIntConfig, BigIntInstructions,
};
use crate::{
    AssignedRSAPubE, AssignedRSAPublicKey, AssignedRSASignature, Fresh, Muled, RSAInstructions,
    RSAPubE, RSAPublicKey, RSASignature, RangeType, RefreshAux, UnassignedInteger,
};
use halo2_gadgets::sha256::{Sha256, Sha256Digest, Sha256Instructions, Table16Chip, Table16Config};
use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value, plonk::Error};
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};

use num_bigint::BigUint;
use std::marker::PhantomData;

/// Configuration for [`BigIntChip`].
#[derive(Clone, Debug)]
pub struct RSAConfig {
    /// Configuration for [`BigIntChip`].
    bigint_config: BigIntConfig,
    table16_config: Table16Config,
}

impl RSAConfig {
    /// Creates new [`RSAConfig`] from [`BigIntConfig`].
    ///
    /// # Arguments
    /// * range_config - a configuration for [`RangeChip`].
    /// * main_gate_config - a configuration for [`MainGate`].
    ///
    /// # Return values
    /// Returns new [`RSAConfig`].
    pub fn new(bigint_config: BigIntConfig, table16_config: Table16Config) -> Self {
        Self {
            bigint_config,
            table16_config,
        }
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
    fn assign_signature(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let c = bigint_chip.assign_integer(ctx, signature.c)?;
        Ok(AssignedRSASignature::new(c))
    }

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

    fn verify_pkcs1v15_signature(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_key: &AssignedRSAPublicKey<F>,
        message: &[AssignedValue<F>],
        signature: &AssignedRSASignature<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let main_gate = self.main_gate();
        let mut is_eq = main_gate.assign_constant(ctx, F::one())?;
        let powed = self.modpow_public_key(ctx, &signature.c, public_key)?;
        let hash_len = 4;
        // 1. Check hashed data
        let table16_chip = self.table16_chip();
        //let sha256 = Sha256::new(table16_chip, ctx.into()).expect("Fail to build a sha256 chip");
        // 64 * 4 = 256 bit, that is the first 4 numbers.

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
                let low = big_to_fe(&big_v % &u32_v);
                let high = big_to_fe(&big_v / &u32_v);
                (low, high)
            })
            .unzip();
        let range_chip = self.range_chip();
        let remain_low = range_chip.assign(ctx, remain_low, 4, 32)?;
        let remain_high = range_chip.assign(ctx, remain_high, 4, 32)?;
        let u32_assign = main_gate.assign_constant(ctx, big_to_fe(u32_v))?;
        let remain_concat = main_gate.mul_add(ctx, &remain_high, &u32_assign, &remain_low)?;
        main_gate.assert_equal(ctx, &powed.limb(hash_len + 2), &remain_concat)?;
        let prefix_32 = main_gate.assign_constant(ctx, big_to_fe(BigUint::from(210504704u32)))?;
        let is_prefix_32_eq = main_gate.is_equal(ctx, &remain_low, &prefix_32)?;
        is_eq = main_gate.and(ctx, &is_eq, &is_prefix_32_eq)?;

        // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
        let ff_32 = main_gate.assign_constant(ctx, big_to_fe(BigUint::from(4294967295u32)))?;
        let is_ff_32_eq = main_gate.is_equal(ctx, &remain_high, &ff_32)?;
        is_eq = main_gate.and(ctx, &is_eq, &is_ff_32_eq)?;
        let ff_64 =
            main_gate.assign_constant(ctx, big_to_fe(BigUint::from(18446744073709551615u64)))?;
        for i in (hash_len + 3)..31 {
            let is_ff_64_eq = main_gate.is_equal(ctx, &powed.limb(i), &ff_64)?;
            is_eq = main_gate.and(ctx, &is_eq, &is_ff_64_eq)?;
        }
        //0b1111111111111111111111111111111111111111111111111 = 0x00 || 0x01 || (0xff)^*
        let last_em =
            main_gate.assign_constant(ctx, big_to_fe(BigUint::from(562949953421311u64)))?;
        let is_last_em_eq = main_gate.is_equal(ctx, &powed.limb(31), &last_em)?;
        is_eq = main_gate.and(ctx, &is_eq, &is_last_em_eq)?;
        Ok(is_eq)
    }
}

impl<F: FieldExt> RSAChip<F> {
    const LIMB_WIDTH: usize = 64;

    /// Create a new [`RSAChip`] from the configuration and parameters.
    ///
    /// # Arguments
    /// * config - a configuration for [`RSAChip`].
    /// * limb_width - the bit length of [`Fresh`] type limbs in this chip.
    /// * bits_len - the default bit length of [`Fresh`] type integers in this chip.
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

    /// Getter for [`Table16Chip`].
    pub fn table16_chip(&self) -> Table16Chip {
        Table16Chip::construct(self.config.table16_config.clone())
    }

    /// Getter for [`RangeChip`].
    pub fn range_chip(&self) -> RangeChip<F> {
        self.bigint_chip().range_chip()
    }

    /// Getter for [`MainGate`].
    pub fn main_gate(&self) -> MainGate<F> {
        self.bigint_chip().main_gate()
    }
}
