use std::marker::PhantomData;

use crate::{AssignedBigUint, BigUintInstructions, CarryModParams, Fresh, Muled, RangeType};

use halo2_base::halo2_proofs::{circuit::Value, plonk::Error};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{
        bigint_to_fe, biguint_to_fe, bit_length, decompose_bigint_option, decompose_biguint,
        fe_to_biguint, modulus, PrimeField,
    },
    AssignedValue, Context,
};
use halo2_ecc::bigint::{carry_mod, mul_no_carry, CRTInteger, FixedCRTInteger, OverflowInteger};

use num_bigint::BigUint;

#[derive(Clone, Debug)]
pub struct BigUintConfig<F: PrimeField> {
    pub range: RangeConfig<F>,
    pub limb_bits: usize,
    native_modulus: BigUint,
}

impl<F: PrimeField> BigUintInstructions<F> for BigUintConfig<F> {
    fn assign_uint(
        &self,
        ctx: &mut Context<'_, F>,
        value: BigUint,
    ) -> Result<AssignedBigUint<F, Fresh>, Error> {
        let num_limbs = self.num_limbs(&value);
        let fixed_crt = FixedCRTInteger::from_native(value, num_limbs, self.limb_bits);
        let crt = fixed_crt.assign(self.gate(), ctx, self.limb_bits, &self.native_modulus);
        Ok(AssignedBigUint::new(crt))
    }

    fn max_value(
        &self,
        ctx: &mut Context<'_, F>,
        num_limbs: usize,
    ) -> Result<AssignedBigUint<F, Fresh>, Error> {
        let value = BigUint::from(1u64) << (self.limb_bits * num_limbs);
        self.assign_uint(ctx, value)
    }

    fn refresh(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigUint<F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedBigUint<F, Fresh>, Error> {
        let p = self.compute_max_mul(num_limbs_l, num_limbs_r);
        let num_limbs = self.num_limbs(&p);
        let carry_mod_params = CarryModParams::<F>::new(self.limb_bits, num_limbs, p);
        Ok(AssignedBigUint::new(self.carry_mod(
            ctx,
            &a.crt,
            carry_mod_params,
        )))
    }
}

impl<F: PrimeField> BigUintConfig<F> {
    /// Construct a new [`BigIntChip`] from the configuration and parameters.
    ///
    /// # Arguments
    ///
    /// # Return values
    /// Returns a new [`BigIntChip`]
    pub fn construct(range: RangeConfig<F>, limb_bits: usize) -> Self {
        let native_modulus = modulus::<F>();
        Self {
            range,
            limb_bits,
            native_modulus,
        }
    }

    /// Getter for [`RangeConfig`].
    pub fn range(&self) -> &RangeConfig<F> {
        &self.range
    }

    /// Getter for [`FlexGateConfig`].
    pub fn gate(&self) -> &FlexGateConfig<F> {
        &self.range.gate
    }

    /// Returns the fewest bits necessary to express the [`BigUint`].
    fn bits_size(val: &BigUint) -> usize {
        val.bits() as usize
    }

    fn num_limbs(&self, val: &BigUint) -> usize {
        let bits = Self::bits_size(&val);
        let num_limbs = if bits % self.limb_bits == 0 {
            bits / self.limb_bits
        } else {
            bits / self.limb_bits + 1
        };
        num_limbs
    }

    // /// Returns the maximum limb size of [`Muled`] type integers.
    // fn compute_mul_word_max(limb_width: usize, min_n: usize) -> BigUint {
    //     let one = BigUint::from(1usize);
    //     let out_base = BigUint::from(1usize) << limb_width;
    //     BigUint::from(min_n) * (&out_base - &one) * (&out_base - &one) + (&out_base - &one)
    // }

    fn compute_max_mul(&self, num_limbs_l: usize, num_limbs_r: usize) -> BigUint {
        let one = BigUint::from(1u64);
        let l_max = (BigUint::from(1u64) << (self.limb_bits * num_limbs_l)) - one;
        let r_max = (BigUint::from(1u64) << (self.limb_bits * num_limbs_r)) - one;
        l_max * r_max
    }

    fn carry_mod(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        carry_mod_params: CarryModParams<F>,
    ) -> CRTInteger<F> {
        carry_mod::crt(
            self.range(),
            ctx,
            &a,
            carry_mod_params.num_limbs_bits,
            &carry_mod_params.p,
            &carry_mod_params.p_limbs,
            carry_mod_params.p_native,
            carry_mod_params.limb_bits,
            &carry_mod_params.limb_bases,
            &carry_mod_params.limb_base_big,
        )
    }
}
