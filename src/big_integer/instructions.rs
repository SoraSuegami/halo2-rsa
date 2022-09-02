use crate::{AssignedInteger, Fresh, Muled, RangeType, UnassignedInteger};
use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use maingate::{AssignedValue, RegionCtx};
use num_bigint::BigUint;

use super::AssignedLimb;

/// Instructions for big-integer operations.
pub trait BigIntInstructions<F: FieldExt> {
    /// Assigns a variable [`AssignedInteger`] whose [`RangeType`] is [`Fresh`].
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: UnassignedInteger<F>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Assigns a constant [`AssignedInteger`] whose [`RangeType`] is [`Fresh`].
    fn assign_constant_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Assigns a constant [`AssignedInteger`] whose [`RangeType`] is [`Muled`].
    fn assign_constant_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
        n1: usize,
        n2: usize,
    ) -> Result<AssignedInteger<F, Muled>, Error>;

    /// Given two inputs `a,b`, performs the addition `a + b`.
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(AssignedInteger<F, Fresh>, AssignedLimb<F, Fresh>), Error>;

    /// Given two inputs `a,b`, performs the subtraction `a - b`.
    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Given two inputs `a,b`, performs the multiplication `a * b`.
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Muled>, Error>;

    /// Given a inputs `a`, performs the square `a^2`.
    fn square(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Muled>, Error> {
        self.mul(ctx, a, a)
    }

    /// Given two inputs `a,b` and a modulus `n`, performs the modular multiplication `a * b mod n`.
    fn mul_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Given a input `a` and a modulus `n`, performs the modular square `a^2 mod n`.
    fn square_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        self.mul_mod(ctx, a, a, n)
    }

    /// Given a base `a`, a variable exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        e: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
        exp_limb_bits: usize,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Given a base `a`, a fixed exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod_fixed_exp(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        e: &BigUint,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Returns an assigned bit representing whether `a` is zero or not.
    fn is_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn is_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    ///Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn is_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Muled>,
        b: &AssignedInteger<F, Muled>,
        n1: usize,
        n2: usize,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` is in the order-`n` finite field.
    fn is_in_field(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Asserts that that `a` is zero or not.
    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn assert_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn assert_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Muled>,
        b: &AssignedInteger<F, Muled>,
        n1: usize,
        n2: usize,
    ) -> Result<(), Error>;

    /// Asserts that `a` is in the order-`n` finite field.
    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error>;
}
