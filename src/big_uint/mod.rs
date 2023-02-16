use std::marker::PhantomData;

mod chip;
mod instructions;
mod utils;
pub use chip::*;
pub use instructions::*;
pub use utils::*;

use halo2_base::{halo2_proofs::circuit::Value, utils::PrimeField};
use halo2_ecc::bigint::CRTInteger;
use num_bigint::BigUint;

pub struct AssignedBigUint<'v, F: PrimeField, T: RangeType> {
    crt: CRTInteger<'v, F>,
    _t: PhantomData<T>,
}

impl<'v, F: PrimeField, T: RangeType> AssignedBigUint<'v, F, T> {
    pub fn new(crt: CRTInteger<'v, F>) -> Self {
        Self {
            crt,
            _t: PhantomData,
        }
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
