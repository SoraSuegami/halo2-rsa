//! A module for big integer operations.
//!
//! A chip in this module, [`BigIntChip`], defines constraints for big integers, i.e. integers whose size is larger than that of the native field of the arithmetic circuit.
//! The big integer consists of multiple values in the native field, and these values are called limbs.
//! The assigned limb and integer, [`AssignedLimb`] and [`AssignedInteger`], have one of the following two range types: [`Fresh`] and [`Muled`].
//! The [`Fresh`] type is allocated to the integers that are not multiplied yet, and the [`Muled`] type is allocated after they are multiplied.
//! We distinguish them to manage the maximum value of the limbs.
//!
//! # Usage
//! The [`BigIntChip`] supports the allocation, addition, subtraction, multiplication, modular multiplication, modular power, comparison, and others of [`AssignedInteger`].
//! Below we explain how to use this chip.
//!
//! ## Chip configuration
//! Before configuring the [`BigIntChip`], you have to create a configuration, [`BigIntConfig`].
//! It depends on [`MainGateConfig`] and [`RangeConfig`].
//! You can compute the `composition_bit_lens` and `overflow_bit_lens` parameters, which are necessary for [`RangeConfig`], using the `BigIntChip::<F>::compute_range_lens` function.
//! The [`BigIntChip`] is created specifying the bit length of the limb (`limb_width`) and that of the big integer (`bits_len`).   
//! ```
//! let main_gate_config = MainGate::<F>::configure(meta);
//! let (composition_bit_lens, overflow_bit_lens) = BigIntChip::<F>::compute_range_lens(
//!    limb_width,
//!    bits_len / limb_width,
//! );
//! let range_config = RangeChip::<F>::configure(
//!     meta,
//!     &main_gate_config,
//!     composition_bit_lens,
//!     overflow_bit_lens,
//! );
//! let bigint_config = BigIntConfig::new(range_config, main_gate_config);
//! let bigint_chip = BigIntChip::new(bigint_config, limb_width, bits_len);
//! ```
//!
//! ## Allocation
//! You can create the [`AssignedInteger`] either from a variable integer or a constant integer.
//! For the variable integer, you first create [`UnassignedInteger`] from limb values, and then assign a new integer by the `assign_integer` function.
//! For the constant integer, you can directly assign it by the `assign_constant_fresh` function.
//! ```
//! let x = BigUint::default();
//! let x_limbs = decompose_big::<F>(x, num_limbs, limb_width);
//! let x_unassigned = UnassignedInteger::from(x_limbs);
//! let x_assigned = bigint_chip.assign_integer(ctx, x_unassigned)?;
//! let c = BigUint::default();
//! let c_assigned = bigint_chip.assign_constant_fresh(ctx, c)?;
//! ```
//!
//! ## Addition and Subtraction
//! To add and subtract [`AssignedInteger`], you only have to call `add` and `sub` functions.
//! The `add` function returns an addition result as [`AssignedInteger`] and a carry as [`AssignedLimb`].
//! The `sub` function returns a subtraction result as [`AssignedInteger`] and an assigned bit as [`AssignedValue`] that represents whether the result is overflowed or not.
//! ```
//! // Assign `a=2`.
//! let a = BigUint::from(2u8);
//! let a_limbs = decompose_big::<F>(a, num_limbs, limb_width);
//! let a_unassigned = UnassignedInteger::from(a_limbs);
//! let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
//! // Assign `b=1`.
//! let b = BigUint::from(1u8);
//! let b_limbs = decompose_big::<F>(b, num_limbs, limb_width);
//! let b_unassigned = UnassignedInteger::from(b_limbs);
//! let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
//! // Assign `c=4`.
//! let c = BigUint::from(4u8);
//! let c_limbs = decompose_big::<F>(c, num_limbs, limb_width);
//! let c_unassigned = UnassignedInteger::from(c_limbs);
//! let c_assigned = bigint_chip.assign_integer(ctx, c_unassigned)?;
//!
//! // Perform `a_b_add = a + b = 3`.
//! let (a_b_add, carry) = bigint_chip.add(ctx, &a_assigned, &b_assigned)?;
//! // Perform `a_b_sub = a - b = 1`. The `is_overflowed` should be zero in this case.
//! let (a_b_sub, is_overflowed) = bigint_chip.sub(ctx, &a_assigned, &b_assigned)?;
//! // Perform `ab_c_sub = a_b_add - c = 3 - 4 < 0`. The `is_overflowed` should be one in this case.
//! let (ab_c_sub, is_overflowed) = bigint_chip.sub(ctx, &a_b_add, &c_assigned)?;
//! ```
//!
mod chip;
mod instructions;
use std::marker::PhantomData;

pub use chip::*;
pub use instructions::*;

use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value};
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};
use num_bigint::BigUint;

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
/// For this reason, we distinguish between these two types of integers.
#[derive(Debug, Clone)]
pub struct Muled {}
impl RangeType for Muled {}

/// An assigned limb of an non native integer.
#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt, T: RangeType>(AssignedValue<F>, PhantomData<T>);

impl<F: FieldExt, T: RangeType> From<AssignedLimb<F, T>> for AssignedValue<F> {
    /// [`AssignedLimb`] can be also represented as [`AssignedValue`].
    fn from(limb: AssignedLimb<F, T>) -> Self {
        limb.0
    }
}

impl<F: FieldExt, T: RangeType> From<&AssignedLimb<F, T>> for AssignedValue<F> {
    /// The reference of [`AssignedLimb`] can be also represented as [`AssignedValue`].
    fn from(limb: &AssignedLimb<F, T>) -> Self {
        limb.0.clone()
    }
}

impl<F: FieldExt, T: RangeType> AssignedLimb<F, T> {
    /// Constructs new [`AssignedLimb`] from an assigned value.
    ///
    /// # Arguments
    /// * value - an assigned value representing a witness value.
    ///
    /// # Return values
    /// Returns a new [`AssignedLimb`].
    pub fn from(value: AssignedValue<F>) -> Self {
        AssignedLimb::<_, T>(value, PhantomData)
    }

    /// Returns the witness value as [`Value<Limb<F>>`].
    pub fn limb(&self) -> Value<Limb<F>> {
        self.0.value().map(|value| Limb::new(*value))
    }

    /// Returns the witness value as [`Value<F>`].
    pub fn value(&self) -> Value<F> {
        self.0.value().cloned()
    }

    /// Returns the witness value as [`Value<BigUint>`].
    pub fn to_big_uint(&self) -> Value<BigUint> {
        self.value().map(|f| fe_to_big(f))
    }

    /// Converts the [`RangeType`] from [`Fresh`] to [`Muled`].
    pub fn to_muled(self) -> AssignedLimb<F, Muled> {
        AssignedLimb::<F, Muled>(self.0, PhantomData)
    }
}

/// Limb that is about to be assigned.
#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt>(F);

impl<F: FieldExt> Limb<F> {
    /// Creates a new [`Limb`]
    ///
    /// # Arguments
    /// * value - a witness value.
    ///
    /// # Return values
    /// Returns a new [`Limb`]
    pub fn new(value: F) -> Self {
        Self(value)
    }
}

/// Witness integer that is about to be assigned.
#[derive(Debug, Clone)]
pub struct UnassignedInteger<F: FieldExt> {
    value: Value<Vec<F>>,
    num_limbs: usize,
}

impl<'a, F: FieldExt> From<Vec<F>> for UnassignedInteger<F> {
    /// Constructs new [`UnassignedInteger`] from a vector of witness values.
    fn from(value: Vec<F>) -> Self {
        let num_limbs = value.len();
        UnassignedInteger {
            value: Value::known(value),
            num_limbs,
        }
    }
}

impl<F: FieldExt> UnassignedInteger<F> {
    /// Returns indexed limb as [`Value<F>`].
    ///
    /// # Arguments
    /// * idx - the index of the limb to retrieve.
    ///
    /// # Return values
    /// Returns the specified limb as [`Value<F>`].
    fn limb(&self, idx: usize) -> Value<F> {
        self.value.as_ref().map(|e| e[idx])
    }

    /// Returns the number of the limbs.
    fn num_limbs(&self) -> usize {
        self.num_limbs
    }
}

/// An assigned witness integer.
#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt, T: RangeType>(Vec<AssignedLimb<F, T>>);

impl<F: FieldExt, T: RangeType> AssignedInteger<F, T> {
    /// Creates a new [`AssignedInteger`].
    ///
    /// # Arguments
    /// * limbs - a vector of [`AssignedLimb`].
    ///
    /// # Return values
    /// Returns a new [`AssignedInteger`].
    pub fn new(limbs: &[AssignedLimb<F, T>]) -> Self {
        AssignedInteger(limbs.to_vec())
    }

    /// Returns assigned limbs.
    pub fn limbs(&self) -> Vec<AssignedLimb<F, T>> {
        self.0.clone()
    }

    /// Returns indexed limb as [`Value`].
    ///
    /// # Arguments
    /// * idx - the index of the limb to retrieve.
    ///
    /// # Return values
    /// Returns the specified limb as [`AssignedValue<F>`].
    fn limb(&self, idx: usize) -> AssignedValue<F> {
        self.0[idx].clone().into()
    }

    /// Returns the number of the limbs.
    pub fn num_limbs(&self) -> usize {
        self.0.len()
    }

    /// Returns the witness value as [`Value<BigUint>`].
    ///
    /// # Arguments
    /// * width - bit length of each limb.
    ///
    /// # Return values
    /// Returns the witness value as [`Value<BigUint>`].
    pub fn to_big_uint(&self, width: usize) -> Value<BigUint> {
        let num_limbs = self.num_limbs();
        (1..num_limbs).fold(
            self.limb(0).value().map(|f| fe_to_big(f.clone())),
            |acc, i| {
                acc + self
                    .limb(i)
                    .value()
                    .map(|f| fe_to_big(f.clone()) << (width * i))
            },
        )
    }

    /// Increases the number of the limbs by adding the given [`AssignedValue<F>`] representing zero.
    ///
    /// # Arguments
    /// * num_extend_limbs - the number of limbs to add.
    /// * zero_value - an assigned value representing zero.
    pub fn extend_limbs(&mut self, num_extend_limbs: usize, zero_value: AssignedValue<F>) {
        let pre_num_limbs = self.num_limbs();
        for _ in 0..num_extend_limbs {
            self.0.push(AssignedLimb::from(zero_value.clone()));
        }
        assert_eq!(pre_num_limbs + num_extend_limbs, self.num_limbs());
    }
}

impl<F: FieldExt> AssignedInteger<F, Fresh> {
    /// Converts the [`RangeType`] from [`Fresh`] to [`Muled`].
    ///
    /// # Arguments
    /// * zero_limb - an assigned limb representing zero.
    pub fn to_muled(&self, zero_limb: AssignedLimb<F, Muled>) -> AssignedInteger<F, Muled> {
        let num_limb = self.num_limbs();
        let mut limbs = self
            .limbs()
            .into_iter()
            .map(|limb| limb.to_muled())
            .collect::<Vec<AssignedLimb<F, Muled>>>();
        for _ in 0..(num_limb - 1) {
            limbs.push(zero_limb.clone())
        }
        AssignedInteger::<F, Muled>::new(&limbs[..])
    }
}

/// Auxiliary data for refreshing a [`Muled`] type integer to a [`Fresh`] type integer.
#[derive(Debug, Clone)]
pub struct RefreshAux {
    pub limb_width: usize,
    pub num_limbs_l: usize,
    pub num_limbs_r: usize,
    pub increased_limbs_vec: Vec<usize>,
}

impl RefreshAux {
    /// Computes `increased_limbs_vec` from `num_limbs_l` and `num_limbs_r`.
    ///
    /// # Arguments
    /// * `limb_width` - bit length of the limb.
    /// * `num_limbs_l` - a parameter to specify the number of limbs.
    /// * `num_limbs_r` - a parameter to specify the number of limbs.
    ///
    /// If `a` (`b`) is the product of integers `l` and `r`, you must specify the lengths of the limbs of integers `l` and `r` as `num_limbs_l` and `num_limbs_l`, respectively.
    ///
    /// # Return values
    /// Returns a new [`RefreshAux`].
    pub fn new(limb_width: usize, num_limbs_l: usize, num_limbs_r: usize) -> Self {
        let max_limb = (BigUint::from(1usize) << limb_width) - BigUint::from(1usize);
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
        let mut max_d = d;
        while cur_d <= max_d {
            let num_chunks = if muled[cur_d].bits() % (limb_width as u64) == 0 {
                muled[cur_d].bits() / (limb_width as u64)
            } else {
                muled[cur_d].bits() / (limb_width as u64) + 1
            } as usize;
            increased_limbs_vec.push(num_chunks - 1);
            if max_d < cur_d + num_chunks - 1 {
                max_d = cur_d + num_chunks - 1;
            }
            let mut chunks = Vec::with_capacity(num_chunks);
            for _ in 0..num_chunks {
                chunks.push(&muled[cur_d] & &max_limb);
                muled[cur_d] = &muled[cur_d] >> limb_width;
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
            limb_width,
            num_limbs_l,
            num_limbs_r,
            increased_limbs_vec,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_refresh_aux_random() {
        let mut rng = thread_rng();
        let limb_width = 32;
        let num_limbs_l = rng.gen::<u8>() as usize;
        let num_limbs_r = rng.gen::<u8>() as usize;
        let refresh_aux_0 = RefreshAux::new(limb_width, num_limbs_l, num_limbs_r);
        let refresh_aux_1 = RefreshAux::new(limb_width, num_limbs_r, num_limbs_l);
        assert_eq!(
            refresh_aux_0.increased_limbs_vec.len(),
            refresh_aux_1.increased_limbs_vec.len()
        );
        let vec0 = refresh_aux_0.increased_limbs_vec;
        let vec1 = refresh_aux_1.increased_limbs_vec;
        for i in 0..vec0.len() {
            assert_eq!(vec0[i], vec1[i]);
        }
    }
}
