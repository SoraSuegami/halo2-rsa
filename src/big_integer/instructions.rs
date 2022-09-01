use crate::{AssignedInteger, Fresh, Muled, RangeType, UnassignedInteger};
use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use maingate::RegionCtx;
use num_bigint::BigUint;

/// Instructions for big-integer operations.
pub trait BigIntInstructions<F: FieldExt> {
    /// Assign a variable integer [`AssignedInteger`] whose [`RangeType`] is [`Fresh`].
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: UnassignedInteger<F>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Assign a constant integer [`AssignedInteger`] whose [`RangeType`] is [`Fresh`].
    fn assign_constant_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Assign a constant integer [`AssignedInteger`] whose [`RangeType`] is [`Muled`].
    fn assign_constant_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
        n1: usize,
        n2: usize,
    ) -> Result<AssignedInteger<F, Muled>, Error>;

    /// Given two inputs `a,b`, performs the multiplication `a*b`.
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Muled>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular multiplication `a*b mod n`.
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
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

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

    /// Asserts that the given `a` and `b` are equivalent, where their range type is `Fresh`.
    fn assert_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that the given `a` and `b` are equivalent, where their range type is `Muled`.
    fn assert_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Muled>,
        b: &AssignedInteger<F, Muled>,
        n1: usize,
        n2: usize,
    ) -> Result<(), Error>;
}
