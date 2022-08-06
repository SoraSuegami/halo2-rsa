use halo2_proofs::arithmetic::FieldExt;
use integer::{rns::Integer, AssignedInteger, IntegerInstructions};
use maingate::halo2::plonk::Error;
use maingate::RegionCtx;

pub trait PowIntegerInstructions<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>: IntegerInstructions<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Exponentiates an [`AssignedInteger`] by a fixed exponent.
    fn pow_fixed(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        exp: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;
}
