use std::marker::PhantomData;

mod chip;
mod instructions;
mod utils;
pub use chip::*;
pub use instructions::*;
pub use utils::*;

use halo2_base::{halo2_proofs::circuit::Value, utils::PrimeField, AssignedValue};
use halo2_ecc::bigint::{CRTInteger, OverflowInteger};
use num_bigint::{BigInt, BigUint};

#[derive(Debug, Clone)]
pub struct AssignedBigInt<'v, F: PrimeField, T: RangeType> {
    crt: CRTInteger<'v, F>,
    _t: PhantomData<T>,
}

impl<'v, F: PrimeField, T: RangeType> AssignedBigInt<'v, F, T> {
    pub fn new(crt: CRTInteger<'v, F>) -> Self {
        Self {
            crt,
            _t: PhantomData,
        }
    }

    pub fn limb(&self, i: usize) -> &AssignedValue<F> {
        &self.crt.truncation.limbs[i]
    }

    pub fn num_limbs(&self) -> usize {
        self.crt.truncation.limbs.len()
    }

    pub fn big_int(&self) -> Value<BigInt> {
        self.crt.value.clone()
    }

    pub fn extend_limbs(&self, num_extend_limbs: usize, zero_value: AssignedValue<'v, F>) -> Self {
        let pre_num_limbs = self.num_limbs();
        let mut limbs = self.crt.truncation.limbs.clone();
        for _ in 0..num_extend_limbs {
            limbs.push(zero_value.clone());
        }
        assert_eq!(pre_num_limbs + num_extend_limbs, limbs.len());
        let truncation = OverflowInteger::construct(limbs, pre_num_limbs + num_extend_limbs);
        let crt =
            CRTInteger::construct(truncation, self.crt.native.clone(), self.crt.value.clone());
        Self::new(crt)
    }

    pub fn crt_ref(&'v self) -> &'v CRTInteger<'v, F> {
        &self.crt
    }
}

impl<'v, F: PrimeField> AssignedBigInt<'v, F, Fresh> {
    pub fn to_muled(self) -> AssignedBigInt<'v, F, Muled> {
        AssignedBigInt::new(self.crt)
    }
}

/// Trait for types representing a range of the limb.
pub trait RangeType: Clone {}

/// [`RangeType`] assigned to [`AssignedLimb`] and [`AssignedInteger`] that are not multiplied yet.
///
/// The maximum value of the [`Fresh`] type limb is defined in the chip implementing [`BigIntInstructions`] trait.
/// For example, [`BigIntChip`] has an `limb_width` parameter and limits the size of the [`Fresh`] type limb to be less than `2^(limb_width)`.
#[derive(Debug, Clone)]
pub struct Fresh {}
impl RangeType for Fresh {}

/// [`RangeType`] assigned to [`AssignedLimb`] and [`AssignedInteger`] that are already multiplied.
///
/// The value of the [`Muled`] type limb may overflow the maximum value of the [`Fresh`] type limb.
/// You can convert the [`Muled`] type integer to the [`Fresh`] type integer by calling [`BigIntInstructions::refresh`] function.
#[derive(Debug, Clone)]
pub struct Muled {}
impl RangeType for Muled {}
