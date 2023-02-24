use crate::{AssignedBigUint, Fresh, Muled, RangeType, RefreshAux};
use halo2_base::halo2_proofs::circuit::Value;
// use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use halo2_base::gates::{flex_gate::FlexGateConfig, range::RangeConfig};
use halo2_base::halo2_proofs::plonk::Error;
use halo2_base::{utils::PrimeField, AssignedValue, Context};
// use maingate::{AssignedValue, RegionCtx};
use num_bigint::BigUint;

/// Instructions for big-integer operations.
pub trait BigUintInstructions<F: PrimeField> {
    /// Return [`FlexGateConfig`]
    fn gate(&self) -> &FlexGateConfig<F>;
    /// Return [`RangeConfig`]
    fn range(&self) -> &RangeConfig<F>;

    /// Return limb bits.
    fn limb_bits(&self) -> usize;

    /// Assigns a variable [`AssignedBigUint`] whose [`RangeType`] is [`Fresh`].
    fn assign_integer<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        value: Value<BigUint>,
        bit_len: usize,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Assigns a constant [`AssignedBigUint`] whose [`RangeType`] is [`Fresh`].
    fn assign_constant<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        value: BigUint,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Assigns the maximum integer whose number of limbs is `num_limbs`.
    fn max_value<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        num_limbs: usize,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Converts a [`Muled`] type integer to a [`Fresh`] type integer.
    fn refresh<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Muled>,
        aux: &RefreshAux,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Given a bit value `sel`, return `a` if `a`=1 and `b` otherwise.
    fn select<'v, T: RangeType>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, T>,
        b: &AssignedBigUint<'v, F, T>,
        sel: &AssignedValue<'v, F>,
    ) -> Result<AssignedBigUint<'v, F, T>, Error>;

    /// Given two inputs `a,b`, performs the addition `a + b`.
    fn add<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Given two inputs `a,b`, performs the subtraction `a - b`.
    /// The result is correct iff `a>=b`.
    fn sub_unsafe<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<(AssignedBigUint<'v, F, Fresh>, AssignedValue<'v, F>), Error>;

    /// Given two inputs `a,b`, performs the multiplication `a * b`.
    fn mul<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedBigUint<'v, F, Muled>, Error>;

    /// Given a inputs `a`, performs the square `a^2`.
    fn square<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedBigUint<'v, F, Muled>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular addition `a + b mod n`.
    fn add_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
        n: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular subtraction `a - b mod n`.
    fn sub_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
        n: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular multiplication `a * b mod n`.
    fn mul_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
        n: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Given a input `a` and a modulus `n`, performs the modular square `a^2 mod n`.
    fn square_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        n: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Given a base `a`, a variable exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        e: &AssignedValue<'v, F>,
        n: &AssignedBigUint<'v, F, Fresh>,
        exp_bits: usize,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Given a base `a`, a fixed exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod_fixed_exp<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        e: &BigUint,
        n: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Returns an assigned bit representing whether `a` is zero or not.
    fn is_zero<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &'v AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error>;

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn is_equal_fresh<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error>;

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn is_equal_muled<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Muled>,
        b: &AssignedBigUint<'v, F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedValue<'v, F>, Error>;

    /// Returns an assigned bit representing whether `a` is less than `b` (`a<b`).
    fn is_less_than<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error>;

    /// Returns an assigned bit representing whether `a` is less than or equal to `b` (`a<=b`).
    fn is_less_than_or_equal<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error>;

    /// Returns an assigned bit representing whether `a` is greater than `b` (`a>b`).
    fn is_greater_than<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error>;

    /// Returns an assigned bit representing whether `a` is greater than or equal to `b` (`a>=b`).
    fn is_greater_than_or_equal<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error>;

    /// Returns an assigned bit representing whether `a` is in the order-`n` finite field.
    fn is_in_field<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error>;

    /// Assert that an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn assert_equal_fresh<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<(), Error>;

    /// Assert that an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn assert_equal_muled<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Muled>,
        b: &AssignedBigUint<'v, F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<(), Error>;

    /// Assert that an assigned bit representing whether `a` is in the order-`n` finite field.
    fn assert_in_field<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigUint<'v, F, Fresh>,
        b: &AssignedBigUint<'v, F, Fresh>,
    ) -> Result<(), Error>;
}
