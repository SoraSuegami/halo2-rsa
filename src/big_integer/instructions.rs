use crate::{AssignedInteger, Fresh, Muled, RangeType, UnassignedInteger};
use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use maingate::RegionCtx;
use num_bigint::BigUint;

pub trait BigIntInstructions<F: FieldExt> {
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: UnassignedInteger<F>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    fn assign_constant_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    fn assign_constant_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
        n1: usize,
        n2: usize,
    ) -> Result<AssignedInteger<F, Muled>, Error>;

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Muled>, Error>;

    fn mul_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    fn square_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    fn pow_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        e: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
        exp_limb_bits: usize,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    fn pow_mod_fixed_exp(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        e: &BigUint,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    fn assert_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error>;

    fn assert_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Muled>,
        b: &AssignedInteger<F, Muled>,
        n1: usize,
        n2: usize,
    ) -> Result<(), Error>;
}
