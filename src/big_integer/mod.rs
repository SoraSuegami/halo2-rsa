mod chip;
mod instructions;
use std::marker::PhantomData;

pub use chip::*;
pub use instructions::*;

use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value};
use maingate::{fe_to_big, AssignedValue};
use num_bigint::BigUint;

pub trait RangeType: Clone {}

#[derive(Debug, Clone)]
pub struct Fresh {}
impl RangeType for Fresh {}

#[derive(Debug, Clone)]
pub struct Muled {}
impl RangeType for Muled {}

/*#[derive(Debug, Clone)]
pub struct Regrouped {}
impl RangeType for Regrouped {}*/

/// AssignedLimb is a limb of an non native integer
#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt, T: RangeType>(AssignedValue<F>, PhantomData<T>);

/// `AssignedLimb` can be also represented as `AssignedValue`
impl<F: FieldExt, T: RangeType> From<AssignedLimb<F, T>> for AssignedValue<F> {
    fn from(limb: AssignedLimb<F, T>) -> Self {
        limb.0
    }
}

/// `AssignedLimb` can be also represented as `AssignedValue`
impl<F: FieldExt, T: RangeType> From<&AssignedLimb<F, T>> for AssignedValue<F> {
    fn from(limb: &AssignedLimb<F, T>) -> Self {
        limb.0.clone()
    }
}

impl<F: FieldExt, T: RangeType> AssignedLimb<F, T> {
    fn value(&self) -> Value<F> {
        self.0.value().cloned()
    }
}

impl<F: FieldExt, T: RangeType> AssignedLimb<F, T> {
    /// Given an assigned value constructs new
    /// `AssignedLimb`
    fn from(value: AssignedValue<F>) -> Self {
        AssignedLimb::<_, T>(value, PhantomData)
    }

    fn limb(&self) -> Value<Limb<F>> {
        self.0.value().map(|value| Limb::new(*value))
    }
}

/// Limb that is about to be assigned.
#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt>(F);

impl<F: FieldExt> Limb<F> {
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
    fn from(value: Vec<F>) -> Self {
        let num_limbs = value.len();
        UnassignedInteger {
            value: Value::known(value),
            num_limbs,
        }
    }
}

impl<F: FieldExt> UnassignedInteger<F> {
    /// Returns indexed limb as `Value`
    fn limb(&self, idx: usize) -> Value<F> {
        self.value.as_ref().map(|e| e[idx])
    }

    fn num_limbs(&self) -> usize {
        self.num_limbs
    }
}

/// An assigned witness integer.
#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt, T: RangeType>(Vec<AssignedLimb<F, T>>);

impl<F: FieldExt, T: RangeType> AssignedInteger<F, T> {
    /// Creates a new [`AssignedInteger`].
    pub fn new(limbs: &[AssignedLimb<F, T>]) -> Self {
        AssignedInteger(limbs.to_vec())
    }

    /// Returns assigned limbs
    pub fn limbs(&self) -> Vec<AssignedLimb<F, T>> {
        self.0.clone()
    }

    /// Returns indexed limb as `Value`
    fn limb(&self, idx: usize) -> AssignedValue<F> {
        self.0[idx].clone().into()
    }

    /// Returns the number of assigned limbs
    pub fn num_limbs(&self) -> usize {
        self.0.len()
    }

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

    pub fn extend_limbs(&mut self, num_extend_limbs: usize, zero_value: AssignedValue<F>) {
        let pre_num_limbs = self.num_limbs();
        for _ in 0..num_extend_limbs {
            self.0.push(AssignedLimb::from(zero_value.clone()));
        }
        assert_eq!(pre_num_limbs + num_extend_limbs, self.num_limbs());
    }
}
