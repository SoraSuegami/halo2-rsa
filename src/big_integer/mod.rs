//! A module for big integer operations.
//!
//! A chip in this module, [`BigIntChip`], defines constraints for big integers, i.e., integers whose size is larger than that of the native field of the arithmetic circuit.
//! The big integer consists of multiple values in the native field, and these values are called limbs.
//! The assigned limb and integer, [`AssignedLimb`] and [`AssignedInteger`], have one of the following two range types: [`Fresh`] and [`Muled`].
//! The [`Fresh`] type is allocated to the integers that are not multiplied yet, and the [`Muled`] type is allocated after they are multiplied.
//! We distinguish them to manage the maximum value of the limbs.
//!
//! # Examples
//! The [`BigIntChip`] supports various operations of [`AssignedInteger`], e.g. allocation, addition, subtraction, multiplication, modular operations, and comparison.
//! Below we present an example of its usage.
//!
//! ```
//! use halo2_rsa::big_integer::{BigIntConfig, BigIntChip, BigIntInstructions, AssignedInteger, Fresh, Muled, RangeType, UnassignedInteger, RefreshAux};
//! use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value, plonk::{Circuit, ConstraintSystem,Error}, circuit::SimpleFloorPlanner};
//! use maingate::{
//!    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
//!    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
//! };
//! use num_bigint::BigUint;
//! use std::marker::PhantomData;
//!
//! #[derive(Debug, Clone)]
//! struct BigIntExample<F:FieldExt> {
//!     // input integers to the circuit.
//!     a: BigUint,
//!     b: BigUint,
//!     c: BigUint,
//!     // a modulus.
//!     n: BigUint,
//!     _f: PhantomData<F>,
//! }
//!
//! impl<F: FieldExt> BigIntExample<F> {
//!     // Each limb of integers in our circuit is 64 bits.
//!     const LIMB_WIDTH: usize = 64;
//!     // The integers in our circuit is 2048 bits.
//!     const BITS_LEN: usize = 2048;
//!     fn bigint_chip(&self, config: BigIntConfig) -> BigIntChip<F> {
//!         BigIntChip::new(config, Self::LIMB_WIDTH, Self::BITS_LEN)
//!     }
//! }
//!
//! impl<F: FieldExt> Circuit<F> for BigIntExample<F> {
//!     // The configuration of our circuit is `BigIntConfig` itself.
//!     type Config = BigIntConfig;
//!     type FloorPlanner = SimpleFloorPlanner;
//!
//!     fn without_witnesses(&self) -> Self {
//!         unimplemented!();
//!     }
//!
//!     // Configures our circuit.
//!     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//!         // 1. Configure `MainGate`.
//!         let main_gate_config = MainGate::<F>::configure(meta);
//!         // 2. Compute bit length parameters by calling `BigIntChip::<F>::compute_range_lens` function.
//!         let (composition_bit_lens, overflow_bit_lens) =
//!         BigIntChip::<F>::compute_range_lens(
//!             Self::LIMB_WIDTH,
//!             Self::BITS_LEN / Self::LIMB_WIDTH,
//!         );
//!         // 3. Configure `RangeChip`.
//!         let range_config = RangeChip::<F>::configure(
//!             meta,
//!             &main_gate_config,
//!             composition_bit_lens,
//!             overflow_bit_lens,
//!         );
//!         // 4. Configure `BigIntConfig`.
//!         BigIntConfig::new(range_config, main_gate_config)
//!     }
//!
//!     // Define constraints for our circuit.
//!     fn synthesize(
//!         &self,
//!         config: Self::Config,
//!         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
//!     ) -> Result<(), Error> {
//!         // Create `BigIntChip`.
//!         let bigint_chip = self.bigint_chip(config);
//!         // The default number of limbs is `Self::BITS_LEN / Self::LIMB_WIDTH = 32`
//!         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
//!
//!         layouter.assign_region(
//!             || "big-integer example",
//!             |region| {
//!                 let offset = 0;
//!                 let ctx = &mut RegionCtx::new(region, offset);
//!                 // 1. Decompose inputs into limbs.
//!                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
//!                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
//!                 let c_limbs = decompose_big::<F>(self.c.clone(), num_limbs, Self::LIMB_WIDTH);
//!                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
//!                 
//!                 // 2. Create `UnassignedInteger` from the limbs.
//!                 let a_unassigned = UnassignedInteger::from(a_limbs);
//!                 let b_unassigned = UnassignedInteger::from(b_limbs);
//!                 let c_unassigned = UnassignedInteger::from(c_limbs);
//!                 let n_unassigned = UnassignedInteger::from(n_limbs);
//!
//!                 // 3. Assign the integers by calling `assign_integer` function.
//!                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
//!                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
//!                 let c_assigned = bigint_chip.assign_integer(ctx, c_unassigned)?;
//!                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
//!
//!                 // 4. We first compute `(a + b) * c`.
//!                 // `a_b_sum = a + b`.
//!                 let a_b_sum = bigint_chip.add(ctx, &a_assigned, &b_assigned)?;
//!                 // `ab_c_mul = a_b_sum * c`. Its range type is defined as `Muled` because its limb value may overflow the maximum value of the `Fresh` type limb.
//!                 let ab_c_mul = bigint_chip.mul(ctx, &a_b_sum, &c_assigned)?;
//!                 // We prepare the auxiliary data for refreshing `ab_c_mul` to a `Fresh` type integer.
//!                 let aux0 = RefreshAux::new(Self::LIMB_WIDTH, a_b_sum.num_limbs(), c_assigned.num_limbs());
//!                 // We convert the range type of `ab_c_mul` from `Muled` to `Fresh` by calling `refresh` function.
//!                 // `val0 = a_b_sum * c = (a + b) * c`
//!                 let val0 = bigint_chip.refresh(ctx, &ab_c_mul, &aux0)?;
//!
//!                 // 5. We then compute `a * c + b * c`.
//!                 // `a_c_mul = a * c`.
//!                 let a_c_mul = bigint_chip.mul(ctx, &a_assigned, &c_assigned)?;
//!                 // We refresh `a_c_mul` to a `Fresh` type integer using the auxiliary data.
//!                 let aux1 = RefreshAux::new(Self::LIMB_WIDTH, a_assigned.num_limbs(), c_assigned.num_limbs());
//!                 let a_c_refreshed = bigint_chip.refresh(ctx, &a_c_mul, &aux1)?;
//!                 // `b_c_mul = b * c`.
//!                 let b_c_mul = bigint_chip.mul(ctx, &b_assigned, &c_assigned)?;
//!                 // We refresh `b_c_mul` to a `Fresh` type integer using the auxiliary data.
//!                 let aux2 = RefreshAux::new(Self::LIMB_WIDTH, b_assigned.num_limbs(), c_assigned.num_limbs());
//!                 let b_c_refreshed = bigint_chip.refresh(ctx, &b_c_mul, &aux2)?;
//!                 // `val1 = a_c_refreshed + b_c_refreshed = a * c + b * c`.
//!                 let val1 = bigint_chip.add(ctx, &a_c_refreshed, &b_c_refreshed)?;
//!                 
//!                 // 6. Assert that `val0` is equal to `val1`.
//!                 bigint_chip.assert_equal_fresh(ctx, &val0, &val1)?;
//!
//!                 // 7. We perform the same computation in the finite field.
//!                 // Assert that inputs are in the order-`n` finite field.
//!                 bigint_chip.assert_in_field(ctx, &a_assigned, &n_assigned)?;
//!                 bigint_chip.assert_in_field(ctx, &b_assigned, &n_assigned)?;
//!                 bigint_chip.assert_in_field(ctx, &c_assigned, &n_assigned)?;
//!                 // `a_b_sum = a + b`.
//!                 let a_b_sum = bigint_chip.add_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
//!                 // `val0 = a_b_sum * c`.
//!                 let val0 = bigint_chip.mul_mod(ctx, &a_b_sum, &c_assigned, &n_assigned)?;
//!                 // `a_c_mul = a * c`.
//!                 let a_c_mul = bigint_chip.mul_mod(ctx, &a_assigned, &c_assigned, &n_assigned)?;
//!                 // `b_c_mul = b * c`.
//!                 let b_c_mul = bigint_chip.mul_mod(ctx, &b_assigned, &c_assigned, &n_assigned)?;
//!                 // `val1 = a_c_mul + b_c_mul`.
//!                 let val1 = bigint_chip.add_mod(ctx, &a_c_mul, &b_c_mul, &n_assigned)?;
//!                 bigint_chip.assert_equal_fresh(ctx, &val0, &val1)?;
//!
//!                 Ok(())
//!             },
//!         )?;
//!         // Create lookup tables for range check in `range_chip`.
//!         let range_chip = bigint_chip.range_chip();
//!         range_chip.load_table(&mut layouter)?;
//!         Ok(())
//!     }
//! }
//!
//! fn main() {
//!     use halo2wrong::halo2::dev::MockProver;
//!     use num_bigint::RandomBits;
//!     use rand::{thread_rng, Rng};
//!     use halo2wrong::curves::pasta::Fp as F;
//!
//!     let mut rng = thread_rng();
//!     let bits_len = BigIntExample::<F>::BITS_LEN as u64;
//!     // 1. Uniformly sample `n` whose bit length is `BigIntExample::<F>::BITS_LEN`.
//!     let mut n = BigUint::default();
//!     while n.bits() != bits_len {
//!         n = rng.sample(RandomBits::new(bits_len));
//!     }
//!     // 2. Uniformly sample `a`, `b`, and `c` from the order-`n` finite field.
//!     let a = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
//!     let b = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
//!     let c = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
//!
//!     // 3. Create our circuit!
//!     let circuit = BigIntExample::<F> {
//!         a,
//!         b,
//!         c,
//!         n,
//!         _f: PhantomData,
//!     };
//!      
//!     // 4. Generate a proof.
//!     let public_inputs = vec![vec![]];
//!     let k = 15;
//!     let prover = match MockProver::run(k, &circuit, public_inputs) {
//!         Ok(prover) => prover,
//!         Err(e) => panic!("{:#?}", e)
//!     };
//!     // 5. Verify the proof.
//!     assert!(prover.verify().is_ok());
//! }
//!

mod chip;
mod instructions;
mod utils;
use std::marker::PhantomData;

pub use chip::*;
pub use instructions::*;
pub use utils::*;

use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value};
use maingate::{fe_to_big, AssignedValue};
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
/// You can convert the [`Muled`] type integer to the [`Fresh`] type integer by calling [`BigIntInstructions::refresh`] function.
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

    /// Returns the witness value as [`AssignedValue<F>`].
    pub fn assigned_val(&self) -> AssignedValue<F> {
        self.0.clone()
    }

    /// Converts the [`RangeType`] from [`Fresh`] to [`Muled`].
    pub fn to_muled(self) -> AssignedLimb<F, Muled> {
        AssignedLimb::<F, Muled>(self.0, PhantomData)
    }
}

/// Witness integer that is about to be assigned.
#[derive(Debug, Clone)]
pub struct UnassignedInteger<F: FieldExt> {
    pub(crate) value: Value<Vec<F>>,
    pub(crate) num_limbs: usize,
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
    pub fn limb(&self, idx: usize) -> AssignedValue<F> {
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

    /// Replaces the specified limb to the given value.
    ///
    /// # Arguments
    /// * idx - index of the modified limb.
    /// * limb - new limb.
    pub fn replace_limb(&mut self, idx: usize, limb: AssignedLimb<F, T>) {
        self.0[idx] = limb;
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
    ///
    /// # Return values
    /// Returns the converted integer whose type is [`AssignedInteger<F, Muled>`].
    /// The number of limbs of the converted integer increases to `2 * num_limb - 1`.
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
    limb_width: usize,
    num_limbs_l: usize,
    num_limbs_r: usize,
    increased_limbs_vec: Vec<usize>,
}

impl RefreshAux {
    /// Creates a new [`RefreshAux`] corresponding to `num_limbs_l` and `num_limbs_r`.
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
        let max_d = d;
        while cur_d <= max_d {
            let num_chunks = if muled[cur_d].bits() % (limb_width as u64) == 0 {
                muled[cur_d].bits() / (limb_width as u64)
            } else {
                muled[cur_d].bits() / (limb_width as u64) + 1
            } as usize;
            increased_limbs_vec.push(num_chunks - 1);
            /*if max_d < cur_d + num_chunks - 1 {
                max_d = cur_d + num_chunks - 1;
            }*/
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
    fn test_debug_and_clone_traits() {
        use halo2wrong::curves::pasta::Fp as F;

        let fresh = Fresh {};
        let fresh = fresh.clone();
        assert_eq!(format!("{fresh:?}"), "Fresh");
        let muled = Muled {};
        let muled = muled.clone();
        assert_eq!(format!("{muled:?}"), "Muled");

        let unassigned_int = UnassignedInteger::from(vec![F::one()]);
        let unassigned_int = unassigned_int.clone();
        assert_eq!(format!("{unassigned_int:?}"), "UnassignedInteger { value: Value { inner: Some([0x0000000000000000000000000000000000000000000000000000000000000001]) }, num_limbs: 1 }");

        let limb_width = 32;
        let num_limbs_l = 1usize;
        let num_limbs_r = 1usize;
        let aux = RefreshAux::new(limb_width, num_limbs_l, num_limbs_r);
        let aux = aux.clone();
        assert_eq!(format!("{aux:?}"),"RefreshAux { limb_width: 32, num_limbs_l: 1, num_limbs_r: 1, increased_limbs_vec: [1, 0] }");
    }

    #[test]
    fn test_refresh_aux_random() {
        let mut rng = thread_rng();
        let limb_width = 32;
        let num_limbs_l = rng.gen::<u8>() as usize + 1usize;
        let num_limbs_r = rng.gen::<u8>() as usize + 1usize;
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
