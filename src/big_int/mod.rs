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

    pub fn limbs(&self) -> Vec<AssignedValue<'v, F>> {
        self.crt.truncation.limbs.clone()
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

impl<'v, F: PrimeField> AssignedBigInt<'v, F, Muled> {
    pub(crate) fn to_fresh_unsafe(self) -> AssignedBigInt<'v, F, Fresh> {
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

/// Auxiliary data for refreshing a [`Muled`] type integer to a [`Fresh`] type integer.
#[derive(Debug, Clone)]
pub struct RefreshAux {
    limb_bits: usize,
    num_limbs_l: usize,
    num_limbs_r: usize,
    increased_limbs_vec: Vec<usize>,
}

impl RefreshAux {
    /// Creates a new [`RefreshAux`] corresponding to `num_limbs_l` and `num_limbs_r`.
    ///
    /// # Arguments
    /// * `limb_bits` - bit length of the limb.
    /// * `num_limbs_l` - a parameter to specify the number of limbs.
    /// * `num_limbs_r` - a parameter to specify the number of limbs.
    ///
    /// If `a` (`b`) is the product of integers `l` and `r`, you must specify the lengths of the limbs of integers `l` and `r` as `num_limbs_l` and `num_limbs_l`, respectively.
    ///
    /// # Return values
    /// Returns a new [`RefreshAux`].
    pub fn new(limb_bits: usize, num_limbs_l: usize, num_limbs_r: usize) -> Self {
        let max_limb = (BigUint::from(1usize) << limb_bits) - BigUint::from(1usize);
        let l_max = vec![max_limb.clone(); num_limbs_l];
        let r_max = vec![max_limb.clone(); num_limbs_r];
        let d = num_limbs_l + num_limbs_r - 1;
        let mut muled = Vec::new();
        for i in 0..d {
            let mut j = if num_limbs_r >= i + 1 {
                0
            } else {
                i + 1 - num_limbs_r
            };
            muled.push(BigUint::from(0usize));
            while j < num_limbs_l && j <= i {
                let k = i - j;
                muled[i] += &l_max[j] * &r_max[k];
                j += 1;
            }
        }
        let mut increased_limbs_vec = Vec::new();
        let mut cur_d = 0;
        let max_d = d;
        while cur_d <= max_d {
            let num_chunks = if muled[cur_d].bits() % (limb_bits as u64) == 0 {
                muled[cur_d].bits() / (limb_bits as u64)
            } else {
                muled[cur_d].bits() / (limb_bits as u64) + 1
            } as usize;
            increased_limbs_vec.push(num_chunks - 1);
            /*if max_d < cur_d + num_chunks - 1 {
                max_d = cur_d + num_chunks - 1;
            }*/
            let mut chunks = Vec::with_capacity(num_chunks);
            for _ in 0..num_chunks {
                chunks.push(&muled[cur_d] & &max_limb);
                muled[cur_d] = &muled[cur_d] >> limb_bits;
            }
            assert_eq!(muled[cur_d], BigUint::from(0usize));
            for j in 0..num_chunks {
                if muled.len() <= cur_d + j {
                    muled.push(BigUint::from(0usize));
                }
                muled[cur_d + j] += &chunks[j];
            }
            cur_d += 1;
        }

        Self {
            limb_bits,
            num_limbs_l,
            num_limbs_r,
            increased_limbs_vec,
        }
    }
}
