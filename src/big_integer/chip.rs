use std::marker::PhantomData;

use crate::{
    AssignedInteger, AssignedLimb, BigIntInstructions, Fresh, Muled, RangeType, RefreshAux,
    UnassignedInteger,
};
use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value, plonk::Error};
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};

use num_bigint::BigUint;

/// Configuration for [`BigIntChip`].
#[derive(Clone, Debug)]
pub struct BigIntConfig {
    /// Configuration for [`RangeChip`].
    range_config: RangeConfig,
    /// Configuration for [`MainGate`].
    main_gate_config: MainGateConfig,
}

impl BigIntConfig {
    /// Creates new [`BigIntConfig`] from [`RangeConfig`] and [`MainGateConfig`].
    ///
    /// # Arguments
    /// * range_config - a configuration for [`RangeChip`].
    /// * main_gate_config - a configuration for [`MainGate`].
    ///
    /// # Return values
    /// Returns new [`BigIntConfig`].
    pub fn new(range_config: RangeConfig, main_gate_config: MainGateConfig) -> Self {
        Self {
            range_config,
            main_gate_config,
        }
    }
}

/// Chip for [`BigIntInstructions`].
#[derive(Debug, Clone)]
pub struct BigIntChip<F: FieldExt> {
    /// Chip configuration.
    config: BigIntConfig,
    /// The width of each limb of the [`Fresh`] type integer in this chip. That is, the limb is an `limb_width`-bits integer.
    limb_width: usize,
    /// The default number of limbs in the [`Fresh`] assigned integer in this chip. It can be changed by arithmetic operations (e.g. `add`, `sub`, `mul`).
    num_limbs: usize,
    _f: PhantomData<F>,
}

impl<F: FieldExt> BigIntInstructions<F> for BigIntChip<F> {
    /// Assigns a variable [`AssignedInteger`] whose [`RangeType`] is [`Fresh`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `integer` - a variable integer to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedInteger`]. The bit length of each limb is less than `self.limb_width`, and the number of its limbs is `self.num_limbs`.
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: UnassignedInteger<F>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let range_gate = self.range_chip();
        let limb_width = self.limb_width;
        let num_limbs = integer.num_limbs();
        // Assign each limb as `AssignedValue`.
        let values = (0..num_limbs)
            .map(|i| {
                let limb = integer.limb(i);
                range_gate.assign(ctx, limb, Self::sublimb_bit_len(limb_width), limb_width)
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let limbs = values
            .into_iter()
            .map(|v| AssignedLimb::from(v))
            .collect::<Vec<AssignedLimb<F, Fresh>>>();
        Ok(self.new_assigned_integer(&limbs))
    }

    /// Assigns a constant [`AssignedInteger`] whose [`RangeType`] is [`Fresh`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `integer` - a constant integer to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedInteger`]. The bit length of each limb is less than `self.limb_width`, and the number of its limbs is `self.num_limbs`.
    ///
    /// # Panics
    /// Panics if the number of limbs of `integer` is greater than `self.num_limbs`.
    fn assign_constant_fresh(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: BigUint,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        // The number of limbs is `self.num_limbs`.
        self.assign_constant(ctx, integer, self.num_limbs)
    }

    /// Assigns a constant [`AssignedInteger`] whose [`RangeType`] is [`Muled`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `integer` - a constant integer to assign.
    /// * `num_limbs_l` - a parameter to specify the number of limbs.
    /// * `num_limbs_r` - a parameter to specify the number of limbs.
    ///
    /// If you consider the returned [`AssignedInteger`] to be the product of integers `l` and `r`, you must specify the lengths of the limbs of integers `l` and `r` as `num_limbs_l` and `num_limbs_l`, respectively.
    ///
    /// # Return values
    /// Returns a new [`AssignedInteger`]. The bit length of each limb is less than `self.limb_width`, and the number of its limbs is `num_limbs_l + num_limbs_r - 1`.
    ///
    /// # Panics
    /// Panics if the number of limbs of `integer` is greater than `num_limbs_l + num_limbs_r - 1`.
    fn assign_constant_muled(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: BigUint,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedInteger<F, Muled>, Error> {
        // The number of limbs is `num_limbs_l + num_limbs_r - 1`.
        self.assign_constant(ctx, integer, num_limbs_l + num_limbs_r - 1)
    }

    /// Assigns the maximum integer whose number of limbs is `num_limbs`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `num_limbs` - the number of limbs.
    ///
    /// # Return values
    /// Returns a new [`AssignedInteger`]. Its each limb is equivalent to `2^(self.limb_width)-1`, and the number of its limbs is `num_limbs`.
    fn max_value(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        num_limbs: usize,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let mut limbs = Vec::with_capacity(num_limbs);
        let one = BigUint::from(1usize);
        // The maximum value of the limb is `1^(self.limb_width) - 1`.
        let limb_max = big_to_fe::<F>((&one << self.limb_width) - &one);
        let main_gate = self.main_gate();
        // Each limb of the new integer is `limb_max`.
        for _ in 0..num_limbs {
            let val = main_gate.assign_constant(ctx, limb_max.clone())?;
            limbs.push(AssignedLimb::from(val));
        }
        Ok(AssignedInteger::new(&limbs))
    }

    /// Converts a [`Muled`] type integer to a [`Fresh`] type integer.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - an assigned integer whose type is [`AssignedInteger<F, Muled>`].
    /// * `aux` - auxiliary data for refreshing a [`Muled`] type integer to a [`Fresh`] type integer.
    ///
    /// # Return values
    /// Returns a refreshed `a` whose type is [`AssignedInteger<F, Fresh>`].
    ///
    /// # Panics
    /// Panics if `self.limb_width` is not equal to `aux.limb_width` or `a.num_limbs()` is not equal to `aux.num_limbs_l + aux.num_limbs_r - 1`.
    fn refresh(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Muled>,
        aux: &RefreshAux,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        // For converting `a` to a [`Fresh`] type integer, we decompose each limb of `a` into `self.limb_width`-bits values.
        assert_eq!(self.limb_width, aux.limb_width);
        // The i-th value of `aux.increased_limbs_vec` represents the number of increased values when converting i-th limb of `a` into `self.limb_width`-bits values.
        let increased_limbs_vec = aux.increased_limbs_vec.clone();
        let num_limbs_l = aux.num_limbs_l;
        let num_limbs_r = aux.num_limbs_r;
        // The following assertion holds since `a` is the product of two integers `l` and `r` whose number of limbs is `num_limbs_l` and `num_limbs_r`, respectively.
        assert_eq!(a.num_limbs(), num_limbs_l + num_limbs_r - 1);
        let num_limbs_fresh = increased_limbs_vec.len();

        let main_gate = self.main_gate();
        let zero_val = main_gate.assign_constant(ctx, F::zero())?;
        let mut refreshed_limbs = Vec::with_capacity(num_limbs_fresh);
        for i in 0..a.num_limbs() {
            refreshed_limbs.push(a.limb(i));
        }
        for _ in 0..(num_limbs_fresh - a.num_limbs()) {
            refreshed_limbs.push(zero_val.clone());
        }
        let limb_max =
            main_gate.assign_constant(ctx, big_to_fe(BigUint::from(1usize) << self.limb_width))?;
        for i in 0..num_limbs_fresh {
            // `i`-th overflowing limb value.
            let mut limb = refreshed_limbs[i].clone();
            for j in 0..(increased_limbs_vec[i] + 1) {
                // `n` is lower `self.limb_width` bits of `limb`.
                // `q` is any other upper bits.
                let (q, n) = self.div_mod_main_gate(ctx, &limb, &limb_max)?;
                if j == 0 {
                    // When `j=0`, `n` is a new `i`-th limb value.
                    refreshed_limbs[i] = n;
                } else {
                    // When `j>0`, `n` is carried to the `i+j`-th limb.
                    refreshed_limbs[i + j] = main_gate.add(ctx, &refreshed_limbs[i + j], &n)?;
                }
                // We use `q` as the next `limb`.
                limb = q;
            }
            // `limb` should be zero because we decomposed all bits of the `i`-th overflowing limb value into `self.limb_width` bits values.
            main_gate.assert_zero(ctx, &limb)?;
        }
        let range_chip = self.range_chip();
        // Assert that the new limb values fit in `self.limb_widt` bits.
        for i in 0..num_limbs_fresh {
            let limb_val = refreshed_limbs[i].value().map(|f| *f);
            let range_assigned = range_chip.assign(
                ctx,
                limb_val,
                Self::sublimb_bit_len(self.limb_width),
                self.limb_width,
            )?;
            main_gate.assert_equal(ctx, &refreshed_limbs[i], &range_assigned)?;
        }
        let refreshed_limbs = refreshed_limbs
            .into_iter()
            .map(|v| AssignedLimb::<F, Fresh>::from(v))
            .collect::<Vec<AssignedLimb<F, Fresh>>>();
        let refreshed = AssignedInteger::new(&refreshed_limbs);
        Ok(refreshed)
    }

    /// Given two inputs `a,b`, performs the addition `a + b`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of addition.
    /// * `b` - input of addition.
    ///
    /// # Return values
    /// Returns the addition result `a + b` as [`AssignedInteger<F, Fresh>`].
    /// The resulting number of limbs is equivalent to `max(a.num_limbs(), b.num_limbs()) + 1`.
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let limb_width = self.limb_width;
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        let max_n = if n1 < n2 { n2 } else { n1 };
        let main_gate = self.main_gate();
        let range_chip = self.range_chip();

        // Align the number of limbs of `a` and `b` by padding with `zero_value`.
        let zero_value = main_gate.assign_constant(ctx, F::zero())?;
        let mut a = a.clone();
        a.extend_limbs(max_n - n1, zero_value.clone());
        let mut b = b.clone();
        b.extend_limbs(max_n - n2, zero_value.clone());

        // Compute a sum and a carry for each limb values.
        let mut c_vals = Vec::with_capacity(max_n);
        let mut carrys = Vec::with_capacity(max_n + 1);
        carrys.push(zero_value);
        let limb_max = BigUint::from(1usize) << limb_width;
        let limb_max_val = main_gate.assign_constant(ctx, big_to_fe(limb_max.clone()))?;
        for i in 0..max_n {
            let a_b = main_gate.add(ctx, &a.limb(i), &b.limb(i))?;
            let sum = main_gate.add(ctx, &a_b, &carrys[i])?;
            let sum_big = sum.value().map(|f| fe_to_big(*f));
            // `c_val_f` is lower `self.limb_width` bits of `a + b + carrys[i]`.
            let c_val_f = sum_big.clone().map(|b| big_to_fe::<F>(b % &limb_max));
            let carry_f = sum_big.map(|b| big_to_fe::<F>(b >> limb_width));
            // `c` and `carry` should fit in `self.limb_widt` bits.
            let c =
                range_chip.assign(ctx, c_val_f, Self::sublimb_bit_len(limb_width), limb_width)?;
            let carry =
                range_chip.assign(ctx, carry_f, Self::sublimb_bit_len(limb_width), limb_width)?;
            let c_add_carry = main_gate.mul_add(ctx, &carry, &limb_max_val, &c)?;
            // `a + b + carrys[i] == c + carry`
            main_gate.assert_equal(ctx, &sum, &c_add_carry)?;
            c_vals.push(c);
            carrys.push(carry);
        }
        // Add the last carry to the `c_vals`.
        c_vals.push(carrys[max_n].clone());
        let c_limbs = c_vals
            .into_iter()
            .map(|v| AssignedLimb::from(v))
            .collect::<Vec<AssignedLimb<F, Fresh>>>();
        let sum = AssignedInteger::new(&c_limbs);
        Ok(sum)
    }

    /// Given two inputs `a,b`, performs the subtraction `a - b`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of subtraction.
    /// * `b` - input of subtraction.
    ///
    /// # Return values
    /// Returns the subtraction result as [`AssignedInteger<F, Fresh>`] and the assigned bit as [`AssignedValue<F, Fresh>`] that represents whether the result is overflowed or not.
    /// If `a>=b`, the result is equivalent to `a - b` and the bit is zero.
    /// Otherwise, the result is equivalent to `b - a` and the bit is one.
    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(AssignedInteger<F, Fresh>, AssignedValue<F>), Error> {
        // Instead of directly computing `a - b`, we first compute `(a + max - b)`, where `max` denotes the maximum integer whose number of limbs is `b.num_limbs()`.
        // It prevents the subtraction　result from being negative.
        let n2 = b.num_limbs();
        let max_int = self.max_value(ctx, n2)?;
        // The number of limbs of `inflated_a` is `max(a.num_limbs(), b.num_limbs()) + 1`.
        let inflated_a = self.add(ctx, a, &max_int)?;
        // The number of limbs of `inflated_subed` is `max(a.num_limbs(), b.num_limbs()) + 1`.
        let inflated_subed = self.sub_unchecked(ctx, &inflated_a, b)?;

        let main_gate = self.main_gate();
        let one = main_gate.assign_bit(ctx, Value::known(F::one()))?;

        // Determine if `a - b` is overflowed by checking the `b.num_limbs()`-th limb of `inflated_subed`.
        // If the limb is equal to one, no overflow is occurring because it implies `(a + max - b) >= max <=> a - b >= 0`.
        let is_not_overflowed = main_gate.is_equal(ctx, &inflated_subed.limb(n2), &one)?;
        let is_overflowed = main_gate.not(ctx, &is_not_overflowed)?;

        let num_limbs_l = inflated_subed.num_limbs();
        let num_limbs_r = if a.num_limbs() > n2 {
            a.num_limbs()
        } else {
            n2
        };
        let zero_value = self.main_gate().assign_constant(ctx, F::zero())?;

        // If `is_not_overflowed=1`, compute `inflated_subed - max_int = a - b`.
        // Otherwise, compute `b - a`.
        let mut sel_l_limbs = Vec::with_capacity(num_limbs_l);
        let mut sel_r_limbs = Vec::with_capacity(num_limbs_r);
        for i in 0..num_limbs_l {
            let val = if i >= n2 {
                main_gate.select(
                    ctx,
                    &inflated_subed.limb(i),
                    &zero_value,
                    &is_not_overflowed,
                )?
            } else {
                main_gate.select(ctx, &inflated_subed.limb(i), &b.limb(i), &is_not_overflowed)?
            };
            sel_l_limbs.push(AssignedLimb::<F, Fresh>::from(val));
        }
        for i in 0..num_limbs_r {
            let val = if i >= a.num_limbs() {
                main_gate.select(ctx, &max_int.limb(i), &zero_value, &is_not_overflowed)?
            } else if i >= n2 {
                main_gate.select(ctx, &zero_value, &a.limb(i), &is_not_overflowed)?
            } else {
                main_gate.select(ctx, &max_int.limb(i), &a.limb(i), &is_not_overflowed)?
            };
            sel_r_limbs.push(AssignedLimb::<F, Fresh>::from(val));
        }

        let sel_l = AssignedInteger::new(&sel_l_limbs);
        let sel_r = AssignedInteger::new(&sel_r_limbs);
        let real_subed = self.sub_unchecked(ctx, &sel_l, &sel_r)?;
        Ok((real_subed, is_overflowed))
    }

    /// Given two inputs `a,b`, performs the multiplication `a - b`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of multiplication.
    /// * `b` - input of multiplication.
    ///
    /// # Return values
    /// Returns the multiplication result `a * b` as [`AssignedInteger<F, Muled>`].
    /// Its range type is [`Muled`] because its limb may overflow the maximum value of the [`Fresh`] type limb, i.e., `2^(self.limb_width)-1`.
    /// Its number of limbs is equivalent to `a.num_limbs() + b.num_limbs() - 1`.
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Muled>, Error> {
        // The following constraints are designed with reference to PolynomialMultiplier template in https://github.com/jacksoom/circom-bigint/blob/master/circuits/mult.circom.
        // However, unlike the circom-bigint implementation, we do not adopt the xJsnark's multiplication technique in https://akosba.github.io/papers/xjsnark.pdf, where the order of constraints is only O(n).
        // This is because addition is not free, i.e., it makes constraints as well as multiplication, in the Plonk constraints system.
        let d0 = a.num_limbs();
        let d1 = b.num_limbs();
        let d = d0 + d1 - 1;
        let main_gate = self.main_gate();
        let mut c_vals = Vec::new();
        for i in 0..d {
            // `acc` denotes the `i`-th limb of the returned integer.
            let mut acc = main_gate.assign_constant(ctx, big_to_fe(BigUint::default()))?;
            let mut j = if d1 >= i + 1 { 0 } else { i + 1 - d1 };
            while j < d0 && j <= i {
                let k = i - j;
                let a_limb = AssignedValue::from(a.limb(j));
                let b_limb = AssignedValue::from(b.limb(k));
                acc = main_gate.mul_add(ctx, &a_limb, &b_limb, &acc)?;
                j += 1;
            }
            c_vals.push(acc);
        }
        let c_limbs = c_vals
            .into_iter()
            .map(|v| AssignedLimb::<_, Muled>::from(v))
            .collect::<Vec<AssignedLimb<F, Muled>>>();
        let c = self.new_assigned_integer(&c_limbs);
        Ok(c)
    }

    /// Given a inputs `a`, performs the square `a^2`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of square.
    ///
    /// # Return values
    /// Returns the square result `a^2` as [`AssignedInteger<F, Muled>`].
    /// Its range type is [`Muled`] because its limb may overflow the maximum value of the [`Fresh`] type limb, i.e., `2^(self.limb_width)-1`.
    /// Its number of limbs is equivalent to `2 * a.num_limbs() - 1`.
    fn square(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Muled>, Error> {
        self.mul(ctx, a, a)
    }

    /// Given two inputs `a,b` and a modulus `n`, performs the modular addition `a + b mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of addition
    /// * `b` - input of addition
    /// * `n` - a modulus
    ///
    /// # Return values
    /// Returns the modular addition result `a + b mod n` as [`AssignedInteger<F, Fresh>`].
    ///
    /// # Requirements
    /// Before calling this function, you must assert that `a<n` and `b<n`.
    fn add_mod(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        // 1. Compute `a + b`.
        // 2. Compute `a + b - n`.
        // 3. If the subtraction is overflowed, i.e., `a + b < n`, returns `a + b`. Otherwise, returns `a + b - n`.
        let mut added = self.add(ctx, a, b)?;
        // The number of limbs of `subed` is `added.num_limbs() = max(a.num_limbs(), b.num_limbs()) + 1`.
        let (subed, is_overflowed) = self.sub(ctx, &added, n)?;
        let num_limbs = subed.num_limbs();
        let zero_value = self.main_gate().assign_constant(ctx, F::zero())?;
        added.extend_limbs(num_limbs - added.num_limbs(), zero_value.clone());
        let mut res_limbs = Vec::with_capacity(num_limbs);
        for i in 0..num_limbs {
            let val =
                self.main_gate()
                    .select(ctx, &added.limb(i), &subed.limb(i), &is_overflowed)?;
            res_limbs.push(AssignedLimb::<_, Fresh>::from(val));
        }
        for i in n.num_limbs()..num_limbs {
            self.main_gate()
                .assert_zero(ctx, &res_limbs[i].assigned_val())?;
        }
        let res = AssignedInteger::new(&res_limbs[0..n.num_limbs()]);
        Ok(res)
    }

    /// Given two inputs `a,b` and a modulus `n`, performs the modular subtraction `a - b mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of subtraction.
    /// * `b` - input of subtraction.
    /// * `n` - a modulus.
    ///
    /// # Return values
    /// Returns the modular subtraction result `a - b mod n` as [`AssignedInteger<F, Fresh>`].
    /// # Requirements
    /// Before calling this function, you must assert that `a<n` and `b<n`.
    fn sub_mod(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        // 1. Compute `a - b`.
        // 2. Compute `n - (b - a) = a - b + n`.
        // 3. If the subtraction in 1 is overflowed, i.e., `a - b < 0`, returns `a - b + n`. Otherwise, returns `a - b`.
        // The number of limbs of `subed1` is `max(a.num_limbs(), b.num_limbs())`.
        let (mut subed1, is_overflowed1) = self.sub(ctx, a, b)?;
        // If `is_overflowed1=1`, `subed2` is equal to `a - b + n` because `subed1` is `b - a` in that case.
        // The number of limbs of `subed2` is `max(n.num_limbs(), subed1.num_limbs()) >= subed1.num_limbs()`.
        let (subed2, is_overflowed2) = self.sub(ctx, n, &subed1)?;
        self.main_gate().assert_zero(ctx, &is_overflowed2)?;
        let num_limbs = subed2.num_limbs();
        let zero_value = self.main_gate().assign_constant(ctx, F::zero())?;
        subed1.extend_limbs(num_limbs - subed1.num_limbs(), zero_value.clone());
        //subed2.extend_limbs(num_limbs - subed2.num_limbs(), zero_value);
        let mut res_limbs = Vec::with_capacity(num_limbs);
        for i in 0..num_limbs {
            let val =
                self.main_gate()
                    .select(ctx, &subed2.limb(i), &subed1.limb(i), &is_overflowed1)?;
            res_limbs.push(AssignedLimb::<_, Fresh>::from(val));
        }
        for i in n.num_limbs()..num_limbs {
            self.main_gate()
                .assert_zero(ctx, &res_limbs[i].assigned_val())?;
        }
        let res = AssignedInteger::new(&res_limbs[0..n.num_limbs()]);
        Ok(res)
    }

    /// Given two inputs `a,b` and a modulus `n`, performs the modular multiplication `a * b mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of multiplication.
    /// * `b` - input of multiplication.
    /// * `n` - a modulus.
    ///
    /// # Return values
    /// Returns the modular multiplication result `a * b mod n` as [`AssignedInteger<F, Fresh>`].
    /// # Requirements
    /// Before calling this function, you must assert that `a<n` and `b<n`.
    fn mul_mod(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        // The following constraints are designed with reference to AsymmetricMultiplierReducer template in https://github.com/jacksoom/circom-bigint/blob/master/circuits/mult.circom.
        // However, we do not regroup multiple limbs like the circom-bigint implementation because addition is not free, i.e., it makes constraints as well as multiplication, in the Plonk constraints system.
        // Besides, we use lookup tables to optimize range checks.
        let limb_width = self.limb_width;
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        assert_eq!(n1, n.num_limbs());
        let (a_big, b_big, n_big) = (
            a.to_big_uint(limb_width),
            b.to_big_uint(limb_width),
            n.to_big_uint(limb_width),
        );
        // 1. Compute the product as `BigUint`.
        let full_prod_big = a_big * b_big;
        // 2. Compute the quotient and remainder when the product is divided by `n`.
        let (mut q_big, mut prod_big) = full_prod_big
            .zip(n_big)
            .map(|(full_prod, n)| (&full_prod / &n, &full_prod % &n))
            .unzip();

        // 3. Decompose the quotient and remainder into `self.limb_width` bits limb values.
        let mut quotients = Vec::new();
        let mut prods = Vec::new();
        let limb_max = BigUint::from(1usize) << limb_width;
        for _ in 0..n2 {
            let q = q_big.as_ref().map(|q| q % &limb_max);
            q_big = q_big.map(|q| q >> limb_width);
            quotients.push(q.map(|b| big_to_fe::<F>(b)));
        }
        for _ in 0..n1 {
            let p = prod_big.as_ref().map(|p| p % &limb_max);
            prod_big = prod_big.map(|p| p >> limb_width);
            prods.push(p.map(|b| big_to_fe::<F>(b)));
        }
        prod_big.map(|b| assert_eq!(b, BigUint::default()));
        q_big.map(|b| assert_eq!(b, BigUint::default()));

        // 4. Assign the quotient and remainder after checking the range of each limb.
        let range_chip = self.range_chip();
        let quotient_assigns = quotients
            .into_iter()
            .map(|q| range_chip.assign(ctx, q, Self::sublimb_bit_len(limb_width), limb_width))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let quotient_limbs = quotient_assigns
            .into_iter()
            .map(|v| AssignedLimb::<F, Fresh>::from(v))
            .collect::<Vec<AssignedLimb<_, _>>>();
        let prod_assigns = prods
            .into_iter()
            .map(|p| range_chip.assign(ctx, p, Self::sublimb_bit_len(limb_width), limb_width))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let prod_limbs = prod_assigns
            .into_iter()
            .map(|v| AssignedLimb::<F, Fresh>::from(v))
            .collect::<Vec<AssignedLimb<_, _>>>();
        let quotient_int = AssignedInteger::new(&quotient_limbs);
        let prod_int = AssignedInteger::new(&prod_limbs);

        // 5. Assert `a * b = quotient_int * n + prod_int`, i.e., `prod_int = (a * b) mod n`.
        let ab = self.mul(ctx, a, b)?;
        let qn = self.mul(ctx, &quotient_int, n)?;
        let n_sum = n1 + n2;
        let mut eq_a_limbs: Vec<AssignedLimb<F, Muled>> = Vec::with_capacity(n_sum - 1);
        let mut eq_b_limbs: Vec<AssignedLimb<F, Muled>> = Vec::with_capacity(n_sum - 1);
        let main_gate = self.main_gate();
        for i in 0..(n_sum - 1) {
            if i < n1 {
                eq_a_limbs.push(AssignedLimb::from(ab.limb(i)));
                let sum = main_gate.add(ctx, &qn.limb(i), &prod_int.limb(i))?;
                eq_b_limbs.push(AssignedLimb::from(sum));
            } else {
                eq_a_limbs.push(AssignedLimb::from(ab.limb(i)));
                eq_b_limbs.push(AssignedLimb::from(qn.limb(i)));
            }
        }
        let eq_a = AssignedInteger::new(&eq_a_limbs);
        let eq_b = AssignedInteger::new(&eq_b_limbs);
        self.assert_equal_muled(ctx, &eq_a, &eq_b, n1, n2)?;

        Ok(prod_int)
    }

    /// Given a input `a` and a modulus `n`, performs the modular square `a^2 mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of square.
    /// * `n` - a modulus.
    ///
    /// # Return values
    /// Returns the modular square result `a^2 mod n` as [`AssignedInteger<F, Fresh>`].
    /// # Requirements
    /// Before calling this function, you must assert that `a<n`.
    fn square_mod(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        self.mul_mod(ctx, a, a, n)
    }

    /// Given a base `a`, a variable exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of square.
    /// * `e` - a variable exponent whose type is [`AssignedInteger<F, Fresh>`].
    /// * `n` - a modulus.
    /// * `exp_limb_bits` - the width of each limb when the e is decomposed.
    ///
    /// # Return values
    /// Returns the modular power result `a^e mod n` as [`AssignedInteger<F, Fresh>`].
    /// # Requirements
    /// Before calling this function, you must assert that `a<n`.
    fn pow_mod(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        e: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
        exp_limb_bits: usize,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let main_gate = self.main_gate();
        // Decompose `e` into bits.
        let e_bits = e
            .limbs()
            .into_iter()
            .map(|limb| main_gate.to_bits(ctx, &limb.assigned_val(), exp_limb_bits))
            .collect::<Result<Vec<Vec<AssignedValue<F>>>, Error>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<AssignedValue<F>>>();
        let mut acc = self.assign_constant_fresh(ctx, BigUint::from(1usize))?;
        let mut squared = a.clone();
        for e_bit in e_bits.into_iter() {
            // Compute `acc * squared`.
            let muled = self.mul_mod(ctx, &acc, &squared, n)?;
            // If `e_bit = 1`, update `acc` to `acc * squared`. Otherwise, use the same `acc`.
            for j in 0..acc.num_limbs() {
                let selected = main_gate.select(ctx, &muled.limb(j), &acc.limb(j), &e_bit)?;
                acc.replace_limb(j, AssignedLimb::from(selected));
            }
            // Square `squared`.
            squared = self.square_mod(ctx, &squared, n)?;
        }
        Ok(acc)
    }

    /// Given a base `a`, a fixed exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of square.
    /// * `e` - a fixed exponent whose type is [`BigUint`].
    /// * `n` - a modulus.
    ///
    /// # Return values
    /// Returns the modular power result `a^e mod n` as [`AssignedInteger<F, Fresh>`].
    /// # Requirements
    /// Before calling this function, you must assert that `a<n`.
    fn pow_mod_fixed_exp(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        e: &BigUint,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let num_e_bits = Self::bits_size(e);
        // Decompose `e` into bits.
        let e_bits = e
            .to_bytes_le()
            .into_iter()
            .flat_map(|v| {
                (0..8)
                    .map(|i: u8| (v >> i) & 1u8 == 1u8)
                    .collect::<Vec<bool>>()
            })
            .collect::<Vec<bool>>();
        let e_bits = e_bits[0..num_e_bits].to_vec();
        let mut acc = self.assign_constant(ctx, BigUint::from(1usize), a.num_limbs())?;
        let mut squared = a.clone();
        for e_bit in e_bits.into_iter() {
            let cur_sq = squared;
            // Square `squared`.
            squared = self.square_mod(ctx, &cur_sq, n)?;
            if !e_bit {
                continue;
            }
            // If `e_bit = 1`, update `acc` to `acc * cur_sq`.
            acc = self.mul_mod(ctx, &acc, &cur_sq, n)?;
        }
        Ok(acc)
    }

    /// Returns an assigned bit representing whether `a` is zero or not.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `a=0`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn is_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        // If all of the limbs of `a` are zero, `assigned_bit` is one. Otherwise, `assigned_bit` is zero.
        let mut assigned_bit = main_gate.assign_bit(ctx, Value::known(F::one()))?;
        for limb in a.limbs().into_iter() {
            let is_zero = main_gate.is_zero(ctx, &limb.assigned_val())?;
            assigned_bit = main_gate.and(ctx, &assigned_bit, &is_zero)?;
        }
        Ok(assigned_bit)
    }

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison whose type is [`AssignedInteger<F, Fresh>`].
    /// * `b` - input of comparison whose type is [`AssignedInteger<F, Fresh>`].
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `a=b`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn is_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        let is_a_larger = n1 > n2;
        let max_n = if is_a_larger { n1 } else { n2 };
        let main_gate = self.main_gate();
        let mut eq_bit = main_gate.assign_bit(ctx, Value::known(F::one()))?;
        for i in 0..max_n {
            // If `i >= n1` or `i >= n1`, `i`-th limb value of the larger integer should be zero.
            // Otherwise, their `i`-th limb value should be the same.
            let flag = if is_a_larger && i >= n2 {
                main_gate.is_zero(ctx, &a.limb(i))?
            } else if !is_a_larger && i >= n1 {
                main_gate.is_zero(ctx, &b.limb(i))?
            } else {
                main_gate.is_equal(ctx, &a.limb(i), &b.limb(i))?
            };
            eq_bit = main_gate.and(ctx, &eq_bit, &flag)?;
        }
        Ok(eq_bit)
    }

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison whose type is [`AssignedInteger<F, Muled>`].
    /// * `b` - input of comparison whose type is [`AssignedInteger<F, Muled>`].
    /// * `num_limbs_l` - a parameter to specify the number of limbs.
    /// * `num_limbs_r` - a parameter to specify the number of limbs.
    ///
    /// If `a` (`b`) is the product of integers `l` and `r`, you must specify the lengths of the limbs of integers `l` and `r` as `num_limbs_l` and `num_limbs_l`, respectively.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `a=b`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn is_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Muled>,
        b: &AssignedInteger<F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedValue<F>, Error> {
        // The following constraints are designed with reference to EqualWhenCarried template in https://github.com/jacksoom/circom-bigint/blob/master/circuits/mult.circom.
        // We use lookup tables to optimize range checks.
        let min_n = if num_limbs_r >= num_limbs_l {
            num_limbs_l
        } else {
            num_limbs_r
        };
        // Each limb of `a` and `b` is less than `min_n * (1^(limb_width) - 1)^2  + (1^(limb_width) - 1)`.
        let word_max = Self::compute_mul_word_max(self.limb_width, min_n);
        let limb_width = self.limb_width;
        let num_limbs = num_limbs_l + num_limbs_r - 1;
        let word_max_width = Self::bits_size(&(&word_max * 2u32));
        let carry_bits = word_max_width - limb_width;
        let main_gate = self.main_gate();
        let range_chip = self.range_chip();

        // The naive approach is to subtract the two integers limb by limb and:
        //  a. Verify that they sum to zero along the way while
        //  b. Propagating carries
        // but this doesn't work because early sums might be negative.
        // So instead we verify that `a - b + word_max = word_max`.
        let limb_max = main_gate.assign_constant(ctx, F::from_u128(1 << limb_width))?;
        let mut accumulated_extra = main_gate.assign_constant(ctx, F::zero())?;
        let mut carry = Vec::with_capacity(num_limbs);
        let mut cs = Vec::with_capacity(num_limbs);
        carry.push(main_gate.assign_constant(ctx, F::zero())?);
        let mut eq_bit = main_gate.assign_bit(ctx, Value::known(F::one()))?;
        for i in 0..num_limbs {
            // `sum = a + b + word_max`
            let a_b = main_gate.sub(ctx, &a.limb(i), &b.limb(i))?;
            let sum =
                main_gate.add_with_constant(ctx, &a_b, &carry[i], big_to_fe(word_max.clone()))?;
            // `c` is lower `self.limb_width` bits of `sum`.
            // `new_carry` is any other upper bits.
            let (new_carry, c) = self.div_mod_main_gate(ctx, &sum, &limb_max)?;
            carry.push(new_carry);
            cs.push(c);

            // `accumulated_extra` is the sum of `word_max`.
            accumulated_extra =
                main_gate.add_constant(ctx, &accumulated_extra, big_to_fe(word_max.clone()))?;
            let (q_acc, mod_acc) = self.div_mod_main_gate(ctx, &accumulated_extra, &limb_max)?;
            // If and only if `a` is equal to `b`, lower `self.limb_width` bits of `sum` and `accumulated_extra` are the same.
            let cs_acc_eq = main_gate.is_equal(ctx, &cs[i], &mod_acc)?;
            eq_bit = main_gate.and(ctx, &eq_bit, &cs_acc_eq)?;
            accumulated_extra = q_acc;

            if i < num_limbs - 1 {
                // Assert that each carry fits in `carry_bits` bits.
                let carry_value = carry[i + 1].value().copied();
                let range_assigned = range_chip.assign(
                    ctx,
                    carry_value,
                    Self::sublimb_bit_len(carry_bits),
                    carry_bits,
                )?;
                let range_eq = main_gate.is_equal(ctx, &carry[i + 1], &range_assigned)?;
                eq_bit = main_gate.and(ctx, &eq_bit, &range_eq)?;
            } else {
                // The final carry should match the `accumulated_extra`.
                let final_carry_eq = main_gate.is_equal(ctx, &carry[i + 1], &accumulated_extra)?;
                eq_bit = main_gate.and(ctx, &eq_bit, &final_carry_eq)?;
            }
        }
        Ok(eq_bit)
    }

    /// Returns an assigned bit representing whether `a` is less than `b` (`a<b`).
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `b` - input of comparison.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `a<b`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn is_less_than(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        // Return if `a<=b` and `a!=b`.
        let is_overflowed = self.is_less_than_or_equal(ctx, a, b)?;
        let is_eq = self.is_equal_fresh(ctx, a, b)?;
        let is_not_eq = self.main_gate().not(ctx, &is_eq)?;
        self.main_gate().and(ctx, &is_overflowed, &is_not_eq)
    }

    /// Returns an assigned bit representing whether `a` is less than or equal to `b` (`a<=b`).
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `b` - input of comparison.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `a<=b`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn is_less_than_or_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        // Return if `a<=b`.
        let (_, is_overflowed) = self.sub(ctx, a, b)?;
        Ok(is_overflowed)
    }

    /// Returns an assigned bit representing whether `a` is greater than `b` (`a>b`).
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `b` - input of comparison.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `a>b`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn is_greater_than(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        // Return if `!(a<=b) <=> a>b`.
        let is_less_than_or_eq = self.is_less_than_or_equal(ctx, a, b)?;
        self.main_gate().not(ctx, &is_less_than_or_eq)
    }

    /// Returns an assigned bit representing whether `a` is greater than or equal to `b` (`a>=b`).
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `b` - input of comparison.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `a>=b`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn is_greater_than_or_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        // Return if `!(a<b) <=> a>=b`.
        let is_less_than = self.is_less_than(ctx, a, b)?;
        self.main_gate().not(ctx, &is_less_than)
    }

    /// Returns an assigned bit representing whether `a` is in the order-`n` finite field.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `n` - a modulus.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `a` is in the order-`n` finite field, in other words `a<n`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn is_in_field(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        // Return if `a<n`, i.e., `0<=a<n`.
        self.is_less_than(ctx, a, n)
    }

    /// Asserts that that `a` is zero or not.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    ///
    /// # Return values
    /// Reutrns [`Error`] if `a!=0`.
    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error> {
        let eq_bit = self.is_zero(ctx, a)?;
        self.main_gate().assert_one(ctx, &eq_bit)
    }

    /// Asserts that `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison whose type is [`AssignedInteger<F, Fresh>`].
    /// * `b` - input of comparison whose type is [`AssignedInteger<F, Fresh>`].
    ///
    /// # Return values
    /// Returns [`Error`] if `a!=b`.
    fn assert_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error> {
        let eq_bit = self.is_equal_fresh(ctx, a, b)?;
        self.main_gate().assert_one(ctx, &eq_bit)
    }

    /// Asserts that `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison whose type is [`AssignedInteger<F, Muled>`].
    /// * `b` - input of comparison whose type is [`AssignedInteger<F, Muled>`].
    ///
    /// # Return values
    /// Returns [`Error`] if `a!=b`.
    fn assert_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Muled>,
        b: &AssignedInteger<F, Muled>,
        n1: usize,
        n2: usize,
    ) -> Result<(), Error> {
        let eq_bit = self.is_equal_muled(ctx, a, b, n1, n2)?;
        self.main_gate().assert_one(ctx, &eq_bit)
    }

    /// Asserts that `a` is less than `b` (`a<b`).
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `b` - input of comparison.
    ///
    /// # Return values
    /// Returns [`Error`] if `a>=b`.
    fn assert_less_than(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error> {
        let eq_bit = self.is_less_than(ctx, a, b)?;
        self.main_gate().assert_one(ctx, &eq_bit)
    }

    /// Asserts that `a` is less than or equal to `b` (`a<=b`).
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `b` - input of comparison.
    ///
    /// # Return values
    /// Returns [`Error`] if `a>b`.
    fn assert_less_than_or_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error> {
        let eq_bit = self.is_less_than_or_equal(ctx, a, b)?;
        self.main_gate().assert_one(ctx, &eq_bit)
    }

    /// Asserts that `a` is greater than `b` (`a>b`).
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `b` - input of comparison.
    ///
    /// # Return values
    /// Returns [`Error`] if `a<=b`.
    fn assert_greater_than(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error> {
        let eq_bit = self.is_greater_than(ctx, a, b)?;
        self.main_gate().assert_one(ctx, &eq_bit)
    }

    /// Asserts that `a` is greater than or equal to `b` (`a>=b`).
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `b` - input of comparison.
    ///
    /// # Return values
    /// Returns [`Error`] if `a<b`.
    fn assert_greater_than_or_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error> {
        let eq_bit = self.is_greater_than_or_equal(ctx, a, b)?;
        self.main_gate().assert_one(ctx, &eq_bit)
    }

    /// Asserts that `a` is in the order-`n` finite field.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `a` - input of comparison.
    /// * `n` - a modulus.
    ///
    /// # Return values
    /// Returns [`Error`] if `a` is not in the order-`n` finite field, i.e., `a>=n`.
    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error> {
        let eq_bit = self.is_in_field(ctx, a, n)?;
        self.main_gate().assert_one(ctx, &eq_bit)
    }
}

impl<F: FieldExt> BigIntChip<F> {
    /// The number of lookup column used in the [`RangeChip`].
    pub(crate) const NUM_LOOKUP_LIMBS: usize = 8;

    /// Create a new [`BigIntChip`] from the configuration and parameters.
    ///
    /// # Arguments
    /// * config - a configuration for [`BigIntChip`].
    /// * limb_width - the bit length of [`Fresh`] type limbs in this chip.
    /// * bits_len - the default bit length of [`Fresh`] type integers in this chip.
    ///
    /// # Return values
    /// Returns a new [`BigIntChip`]
    pub fn new(config: BigIntConfig, limb_width: usize, bits_len: usize) -> Self {
        assert_eq!(bits_len % limb_width, 0);
        let num_limbs = bits_len / limb_width;
        let max_word = Self::compute_mul_word_max(limb_width, num_limbs);
        assert!(Self::bits_size(&max_word) <= F::NUM_BITS as usize);
        BigIntChip {
            config,
            limb_width,
            num_limbs,
            _f: PhantomData,
        }
    }

    /// Getter for [`RangeChip`].
    pub fn range_chip(&self) -> RangeChip<F> {
        RangeChip::<F>::new(self.config.range_config.clone())
    }

    /// Getter for [`MainGate`].
    pub fn main_gate(&self) -> MainGate<F> {
        let main_gate_config = self.config.main_gate_config.clone();
        MainGate::<F>::new(main_gate_config)
    }

    /// Creates a new [`AssignedInteger`] from its limb representation.
    ///
    /// # Arguments
    /// * limbs - the assigned limbs of the integer.
    ///
    /// # Return values
    /// Returns a new [`AssignedInteger`]
    pub(crate) fn new_assigned_integer<T: RangeType>(
        &self,
        limbs: &[AssignedLimb<F, T>],
    ) -> AssignedInteger<F, T> {
        AssignedInteger::new(limbs)
    }

    /// Returns the bit length parameters necessary to configure the [`RangeChip`].
    ///
    /// # Arguments
    /// * limb_width - the bit length of [`Fresh`] limbs.
    /// * num_limbs - the default number of limbs of [`Fresh`] integers.
    ///
    /// # Return values
    /// Returns a vector of composition bit lengthes (`composition_bit_lens`) and a vector of overflow bit lengthes (`overflow_bit_lens`), which are necessary for [`RangeConfig`].
    pub fn compute_range_lens(limb_width: usize, num_limbs: usize) -> (Vec<usize>, Vec<usize>) {
        let out_comp_bit_len = limb_width / BigIntChip::<F>::NUM_LOOKUP_LIMBS;
        let out_overflow_bit_len = limb_width % out_comp_bit_len;
        let one = BigUint::from(1usize);
        let out_base = BigUint::from(1usize) << limb_width;

        let fresh_word_max_width = (2u32 * &out_base).bits() as usize;
        let fresh_carry_bits = fresh_word_max_width - limb_width;
        let fresh_carry_comp_bit_len = BigIntChip::<F>::sublimb_bit_len(fresh_carry_bits);
        let fresh_carry_overflow_bit_len = fresh_carry_bits % fresh_carry_comp_bit_len;

        let mul_word_max =
            BigUint::from(num_limbs) * (&out_base - &one) * (&out_base - &one) + (&out_base - &one);
        let mul_word_max_width = (&mul_word_max * 2u32).bits() as usize;
        let mul_carry_bits = mul_word_max_width - limb_width;
        let mul_carry_comp_bit_len = BigIntChip::<F>::sublimb_bit_len(mul_carry_bits);
        let mul_carry_overflow_bit_len = mul_carry_bits % mul_carry_comp_bit_len;

        let composition_bit_lens = vec![
            out_comp_bit_len,
            fresh_carry_comp_bit_len,
            mul_carry_comp_bit_len,
        ];
        let overflow_bit_lens = vec![
            out_overflow_bit_len,
            fresh_carry_overflow_bit_len,
            mul_carry_overflow_bit_len,
        ];
        (composition_bit_lens, overflow_bit_lens)
    }

    /// Generic function to assign a constant integer.
    fn assign_constant<T: RangeType>(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: BigUint,
        max_num_limbs: usize,
    ) -> Result<AssignedInteger<F, T>, Error> {
        let limb_width = self.limb_width;
        let int_bits_size = Self::bits_size(&integer);
        let is_fit = int_bits_size % limb_width == 0;
        let num_limbs = if is_fit {
            int_bits_size / limb_width
        } else {
            int_bits_size / limb_width + 1
        };
        assert!(num_limbs <= max_num_limbs);
        // Decompose `integer` into limb values.
        let limbs = decompose_big::<F>(integer, num_limbs, limb_width);
        let main_gate = self.main_gate();
        let mut assigned_limbs: Vec<AssignedLimb<F, T>> = Vec::with_capacity(num_limbs);

        for limb in limbs.iter() {
            let assigned = main_gate.assign_constant(ctx, *limb)?;
            assigned_limbs.push(AssignedLimb::from(assigned));
        }
        let zero = AssignedLimb::<F, T>::from(self.main_gate().assign_constant(ctx, F::zero())?);
        for _ in 0..(max_num_limbs - num_limbs) {
            assigned_limbs.push(zero.clone());
        }
        Ok(AssignedInteger::new(&assigned_limbs))
    }

    /// Given two inputs `a,b` (`a>=b`), performs the subtraction `a - b`.
    /// # Panics
    /// Panics if `a<b`.
    fn sub_unchecked(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let limb_width = self.limb_width;
        // If `a.num_limbs() < b.num_limbs()`, in other words `a < b`, this function will panic.
        assert!(a.num_limbs() >= b.num_limbs());
        let max_n = a.num_limbs();
        let range_chip = self.range_chip();
        let a_big = a.to_big_uint(limb_width);
        let b_big = b.to_big_uint(limb_width);
        // If `a<b`, the following subtraction will panic.
        let mut c_big = a_big - b_big;

        let mut c_limbs = Vec::with_capacity(max_n);
        let limb_max = BigUint::from(1usize) << limb_width;
        for _ in 0..max_n {
            // Assert that each limb fits in `limb_width` bits.
            let c_f = c_big.as_ref().map(|b| big_to_fe::<F>(b % &limb_max));
            let c_val =
                range_chip.assign(ctx, c_f, Self::sublimb_bit_len(limb_width), limb_width)?;
            c_limbs.push(AssignedLimb::<_, Fresh>::from(c_val));
            c_big = c_big.map(|b| b >> limb_width);
        }
        let c = AssignedInteger::new(&c_limbs);

        // Assert that `a = b + c`.
        let added = self.add(ctx, b, &c)?;
        self.assert_equal_fresh(ctx, a, &added)?;
        Ok(c)
    }

    /// Given a integer `a` and a divisor `n`, performs `a/n` and `a mod n`.
    /// # Panics
    /// Panics if `n=0`.
    fn div_mod_main_gate(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        n: &AssignedValue<F>,
    ) -> Result<(AssignedValue<F>, AssignedValue<F>), Error> {
        let main_gate = self.main_gate();
        let (q_unassigned, a_mod_n_unassigned) = a
            .value()
            .zip(n.value())
            .map(|(a, n)| {
                let a_big = fe_to_big(a.clone());
                let n_big = fe_to_big(n.clone());
                let q_big = &a_big / &n_big;
                let a_mod_n_big = &a_big % &n_big;
                (big_to_fe::<F>(q_big), big_to_fe::<F>(a_mod_n_big))
            })
            .unzip();
        let (q, a_mod_n) = (
            main_gate.assign_value(ctx, q_unassigned)?,
            main_gate.assign_value(ctx, a_mod_n_unassigned)?,
        );
        let nq = main_gate.mul(ctx, n, &q)?;
        let a_sub_nq = main_gate.sub(ctx, a, &nq)?;
        main_gate.assert_equal(ctx, &a_mod_n, &a_sub_nq)?;
        Ok((q, a_mod_n))
    }

    /// Returns the fewest bits necessary to express the [`BigUint`].
    fn bits_size(val: &BigUint) -> usize {
        val.bits() as usize
    }

    /// Returns the bit length of the sublimb necessary to check the range of the `bit_len_limb`-bits integer with [`RangeChip`].
    fn sublimb_bit_len(bit_len_limb: usize) -> usize {
        //assert!(bit_len_limb % Self::NUM_LOOKUP_LIMBS == 0);
        let val = bit_len_limb / Self::NUM_LOOKUP_LIMBS;
        if val == 0 {
            1
        } else {
            val
        }
    }

    /// Returns the maximum limb size of [`Muled`] type integers.
    fn compute_mul_word_max(limb_width: usize, min_n: usize) -> BigUint {
        let one = BigUint::from(1usize);
        let out_base = BigUint::from(1usize) << limb_width;
        BigUint::from(min_n) * (&out_base - &one) * (&out_base - &one) + (&out_base - &one)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::big_pow_mod;
    use halo2wrong::halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };

    macro_rules! impl_bigint_test_circuit {
        ($circuit_name:ident, $test_fn_name:ident, $limb_width:expr, $bits_len:expr, $should_be_error:expr, $( $synth:tt )*) => {
            struct $circuit_name<F: FieldExt> {
                a: BigUint,
                b: BigUint,
                n: BigUint,
                _f: PhantomData<F>,
            }

            impl<F: FieldExt> $circuit_name<F> {
                const LIMB_WIDTH: usize = $limb_width;
                const BITS_LEN: usize = $bits_len;
                fn bigint_chip(&self, config: BigIntConfig) -> BigIntChip<F> {
                    BigIntChip::new(config, Self::LIMB_WIDTH, Self::BITS_LEN)
                }
            }

            impl<F: FieldExt> Circuit<F> for $circuit_name<F> {
                type Config = BigIntConfig;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let main_gate_config = MainGate::<F>::configure(meta);
                    let (composition_bit_lens, overflow_bit_lens) =
                        BigIntChip::<F>::compute_range_lens(
                            Self::LIMB_WIDTH,
                            Self::BITS_LEN / Self::LIMB_WIDTH,
                        );
                    let range_config = RangeChip::<F>::configure(
                        meta,
                        &main_gate_config,
                        composition_bit_lens,
                        overflow_bit_lens,
                    );
                    BigIntConfig::new(range_config, main_gate_config)
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                use halo2wrong::halo2::dev::MockProver;
                use num_bigint::RandomBits;
                use rand::{thread_rng, Rng};
                fn run<F: FieldExt>() {
                    let mut rng = thread_rng();
                    let bits_len = $circuit_name::<F>::BITS_LEN as u64;
                    let mut n = BigUint::default();
                    while n.bits() != bits_len {
                        n = rng.sample(RandomBits::new(bits_len));
                    }
                    let a = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                    let b = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                    let circuit = $circuit_name::<F> {
                        a,
                        b,
                        n,
                        _f: PhantomData,
                    };

                    let public_inputs = vec![vec![]];
                    let k = 16;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }

                use halo2wrong::curves::bn256::Fq as BnFq;
                use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
                run::<BnFq>();
                run::<PastaFp>();
                run::<PastaFq>();
            }
        };
    }

    impl_bigint_test_circuit!(
        TestAddCircuit,
        test_add_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random add test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let sum = &self.a + &self.b;
                    //let carry = &all_sum >> Self::BITS_LEN;
                    //let base = BigUint::from(1usize) << Self::BITS_LEN;
                    //let sum = &all_sum - &carry * &base;
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let sum_assigned_int =
                        bigint_chip.assign_constant(ctx, sum, Self::BITS_LEN + 1)?;
                    let added = bigint_chip.add(ctx, &a_assigned, &b_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &sum_assigned_int, &added)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestButAddCircuit,
        test_but_add_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random add test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let added = bigint_chip.add(ctx, &a_assigned, &b_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &a_assigned, &added)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestSubCircuit,
        test_sub_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random sub test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let b: BigUint = &self.b >> 8;
                    let sub = &self.a - &b;
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let sub_assigned_int = bigint_chip.assign_constant_fresh(ctx, sub)?;
                    let (subed, is_overflowed) = bigint_chip.sub(ctx, &a_assigned, &b_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &sub_assigned_int, &subed)?;
                    bigint_chip.main_gate().assert_zero(ctx, &is_overflowed)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestOverflowSubCircuit,
        test_overflow_sub_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random sub test with an overflow case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = &self.a >> 1024;
                    let b: BigUint = self.b.clone();
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let (_, is_overflowed) = bigint_chip.sub(ctx, &a_assigned, &b_assigned)?;
                    bigint_chip.main_gate().assert_one(ctx, &is_overflowed)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadSubCircuit,
        test_bad_sub_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random sub test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let b: BigUint = &self.b >> 8;
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
                    let (subed, _) = bigint_chip.sub(ctx, &a_assigned, &b_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &zero, &subed)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCircuit,
        test_mul_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random mul test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMuledEqualCircuit,
        test_muled_equal_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_equal_muled test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let ba = bigint_chip.mul(ctx, &b_assigned, &a_assigned)?;
                    bigint_chip.assert_equal_muled(
                        ctx,
                        &ab,
                        &ba,
                        a_assigned.num_limbs(),
                        b_assigned.num_limbs(),
                    )?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadMuledEqualCircuit,
        test_bad_muled_equal_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_equal_muled test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    assert!(self.a != BigUint::from(0usize));
                    assert!(self.b != BigUint::from(0usize));
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let zero = bigint_chip.assign_constant_muled(
                        ctx,
                        BigUint::from(0usize),
                        num_limbs,
                        num_limbs,
                    )?;
                    bigint_chip.assert_equal_muled(
                        ctx,
                        &ab,
                        &zero,
                        a_assigned.num_limbs(),
                        b_assigned.num_limbs(),
                    )?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestFreshEqualCircuit,
        test_fresh_equal_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_equal_fresh test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a1_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a1_unassigned = UnassignedInteger::from(a1_limbs);
                    let a2_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a2_unassigned = UnassignedInteger::from(a2_limbs);
                    let a1_assigned = bigint_chip.assign_integer(ctx, a1_unassigned)?;
                    let a2_assigned = bigint_chip.assign_integer(ctx, a2_unassigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &a1_assigned, &a2_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadFreshEqualCircuit,
        test_bad_fresh_equal_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_equal_fresh test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    assert!(self.a != BigUint::from(0usize));
                    let a1_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a1_unassigned = UnassignedInteger::from(a1_limbs);
                    let a1_assigned = bigint_chip.assign_integer(ctx, a1_unassigned)?;
                    let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
                    bigint_chip.assert_equal_fresh(ctx, &a1_assigned, &zero)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestRefreshCircuit,
        test_refresh_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random refresh test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let ba = bigint_chip.mul(ctx, &b_assigned, &a_assigned)?;
                    let aux = RefreshAux::new(Self::LIMB_WIDTH, num_limbs, num_limbs);
                    let ab_refreshed = bigint_chip.refresh(ctx, &ab, &aux)?;
                    let ba_refreshed = bigint_chip.refresh(ctx, &ba, &aux)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab_refreshed, &ba_refreshed)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestThreeMulCircuit,
        test_three_mul_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "multiplication test with three integers",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let bn = bigint_chip.mul(ctx, &b_assigned, &n_assigned)?;
                    let aux = RefreshAux::new(Self::LIMB_WIDTH, num_limbs, num_limbs);
                    let ab_refreshed = bigint_chip.refresh(ctx, &ab, &aux)?;
                    let bn_refreshed = bigint_chip.refresh(ctx, &bn, &aux)?;
                    let num1 = ab_refreshed.num_limbs();
                    let num2 = n_assigned.num_limbs();
                    let ab_n = bigint_chip.mul(ctx, &ab_refreshed, &n_assigned)?;
                    let bn_a = bigint_chip.mul(ctx, &bn_refreshed, &a_assigned)?;
                    bigint_chip.assert_equal_muled(ctx, &ab_n, &bn_a, num1, num2)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestAddModCircuit,
        test_add_mod_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random add_mod test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.add_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let ba = bigint_chip.add_mod(ctx, &b_assigned, &a_assigned, &n_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &ba)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadAddModCircuit,
        test_bad_add_mod_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random add_mod test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.add_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &n_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestSubModCircuit,
        test_sub_mod_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random sub_mod test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let sub = if &self.a >= &self.b {
                        &self.a - &self.b
                    } else {
                        &self.a + &self.n - &self.b
                    };
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.sub_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let sub_assigned = bigint_chip.assign_constant_fresh(ctx, sub)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &sub_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestSubModOverflowCircuit,
        test_sub_mod_overflow_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random sub_mod overflow test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs =
                        decompose_big::<F>(self.n.clone() >> 1024, num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    bigint_chip.sub_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadSubModCircuit,
        test_bad_sub_mod_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random sub_mod test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.sub_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &n_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModEqualCircuit,
        test_module_mul_equal_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random mul_mod test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let ba = bigint_chip.mul_mod(ctx, &b_assigned, &a_assigned, &n_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &ba)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadMulModEqualCircuit,
        test_bad_module_mul_equal_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random mul_mod test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &n_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestPowModCircuit,
        test_pow_mod_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random pow_mod test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let e_bit = 5;
                    let e: BigUint =
                        self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let e_assigned = bigint_chip.assign_constant(ctx, e.clone(), 1)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let powed =
                        bigint_chip.pow_mod(ctx, &a_assigned, &e_assigned, &n_assigned, e_bit)?;
                    let ans_big = big_pow_mod(&self.a, &e, &self.n);
                    let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
                    bigint_chip.assert_equal_fresh(ctx, &powed, &ans_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadPowModCircuit,
        test_bad_pow_mod_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random pow_mod test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let e_bit = 5;
                    let e: BigUint =
                        self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let e_assigned = bigint_chip.assign_constant(ctx, e.clone(), 1)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let powed =
                        bigint_chip.pow_mod(ctx, &a_assigned, &e_assigned, &n_assigned, e_bit)?;
                    let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
                    bigint_chip.assert_equal_fresh(ctx, &powed, &zero)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestPowModFixedExpCircuit,
        test_pow_mod_fixed_exp_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random pow_mod test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let e_bit = 7;
                    let e: BigUint =
                        self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let powed = bigint_chip.pow_mod_fixed_exp(ctx, &a_assigned, &e, &n_assigned)?;
                    let ans_big = big_pow_mod(&self.a, &e, &self.n);
                    let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
                    bigint_chip.assert_equal_fresh(ctx, &powed, &ans_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadPowModFixedExpCircuit,
        test_bad_pow_mod_fixed_exp_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random pow_mod test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let e_bit = 7;
                    let e: BigUint =
                        self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let powed = bigint_chip.pow_mod_fixed_exp(ctx, &a_assigned, &e, &n_assigned)?;
                    let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
                    bigint_chip.assert_equal_fresh(ctx, &powed, &zero)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestIsZeroCircuit,
        test_is_zero_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random is_zero test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    assert!(self.a != BigUint::from(0usize));
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
                    bigint_chip.assert_zero(ctx, &zero)?;
                    let a_is_zero = bigint_chip.is_zero(ctx, &a_assigned)?;
                    let main_gate = bigint_chip.main_gate();
                    main_gate.assert_zero(ctx, &a_is_zero)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestLessThanCircuit,
        test_less_than_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_less_than test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = &self.a >> 128;
                    let b = self.b.clone();
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.assert_less_than(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadLessThanCircuit,
        test_bad_less_than_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_less_than test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = self.a.clone();
                    let b = self.b.clone() >> 128;
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.assert_less_than(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestLessThanOrEqualCircuit,
        test_less_than_or_equal_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_less_than_or_equal test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = self.a.clone();
                    let b = self.a.clone();
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.assert_less_than_or_equal(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadLessThanOrEqualCircuit,
        test_bad_less_than_or_equal_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_less_than_or_equal test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = self.a.clone();
                    let b = self.b.clone() >> 128;
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.assert_less_than_or_equal(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestGreaterThanCircuit,
        test_greater_than_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_greater_than test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = self.a.clone();
                    let b = self.a.clone() >> 128;
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.assert_greater_than(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadGreaterThanCircuit,
        test_bad_greater_than_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_greater_than test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = self.a.clone() >> 128;
                    let b = self.b.clone();
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.assert_greater_than(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestGreaterThanOrEqualCircuit,
        test_greater_than_or_equal_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_greater_than_or_equal test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = self.a.clone();
                    let b = self.a.clone();
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.assert_greater_than_or_equal(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadGreaterThanOrEqualCircuit,
        test_bad_greater_than_or_equal_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_greater_than_or_equal test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a = self.a.clone() >> 128;
                    let b = self.b.clone();
                    let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.assert_greater_than_or_equal(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestInFieldCircuit,
        test_in_field_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_in_field test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    bigint_chip.assert_in_field(ctx, &a_assigned, &n_assigned)?;
                    let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
                    bigint_chip.assert_in_field(ctx, &zero, &n_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestBadInFieldCircuit,
        test_bad_in_field_circuit,
        64,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "random assert_in_field test with an error case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    bigint_chip.assert_in_field(ctx, &n_assigned, &n_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase1Circuit,
        test_mul_case1,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "1 * 1 = 1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let one = bigint_chip.assign_constant_fresh(ctx, BigUint::from(1usize))?;
                    let n = one.num_limbs();
                    let one_muled = bigint_chip.mul(ctx, &one, &one)?;
                    let zero = AssignedLimb::from(
                        bigint_chip.main_gate().assign_constant(ctx, F::zero())?,
                    );
                    bigint_chip.assert_equal_muled(ctx, &one.to_muled(zero), &one_muled, n, n)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase3Circuit,
        test_mul_case3,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "(1+0x+3x^2)(3+1x) = 3+1x+9x^2+3x^3",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
                    let a_big =
                        BigUint::from(1usize) + 0usize * &out_base + 3usize * &out_base * &out_base;
                    let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
                    let n1 = a_assigned.num_limbs();
                    let b_big =
                        BigUint::from(3usize) + 1usize * &out_base + 0usize * &out_base * &out_base;
                    let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
                    let n2 = b_assigned.num_limbs();
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let ans_big = BigUint::from(3usize)
                        + 1usize * &out_base
                        + 9usize * &out_base * &out_base
                        + 3usize * &out_base * &out_base * &out_base;
                    let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n2)?;
                    bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n2)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase4Circuit,
        test_mul_case4,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "(3 + 4x + 5x^2 + 6x^3)(9 + 10x + 11x^2 + 12x^3) =  27 + 66 x  + 118 x^2 + 184 x^3 + 163 x^4 + 126 x^5 + 72 x^6 ",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
                    let a_big =
                        BigUint::from(3usize) + 4usize * &out_base + 5usize * &out_base.pow(2) + 6usize * &out_base.pow(3);
                    let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
                    let n1 = a_assigned.num_limbs();
                    let b_big =
                        BigUint::from(9usize) + 10usize * &out_base + 11usize * &out_base.pow(2) + 12usize * &out_base.pow(3);
                    let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
                    let n2 = b_assigned.num_limbs();
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let ans_big = BigUint::from(27usize) + 66usize * &out_base + 118usize * &out_base.pow(2u32) + 184usize * &out_base.pow(3u32) + 163usize * &out_base.pow(4u32) + 126usize * &out_base.pow(5u32) + 72usize * &out_base.pow(6u32);
                    let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n2)?;
                    bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n2)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase5Circuit,
        test_mul_case5,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "big square test",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
                    let a_big = BigUint::from(4819187580044832333u128)
                        + 9183764011217009606u128 * &out_base
                        + 11426964127496009747u128 * &out_base.pow(2)
                        + 17898263845095661790u128 * &out_base.pow(3)
                        + 12102522037140783322u128 * &out_base.pow(4)
                        + 4029304176671511763u128 * &out_base.pow(5)
                        + 11339410859987005436u128 * &out_base.pow(6)
                        + 12120243430436644729u128 * &out_base.pow(7)
                        + 2888435820322958146u128 * &out_base.pow(8)
                        + 7612614626488966390u128 * &out_base.pow(9)
                        + 3872170484348249672u128 * &out_base.pow(10)
                        + 9589147526444685354u128 * &out_base.pow(11)
                        + 16391157694429928307u128 * &out_base.pow(12)
                        + 12256166884204507566u128 * &out_base.pow(13)
                        + 4257963982333550934u128 * &out_base.pow(14)
                        + 916988490704u128 * &out_base.pow(15);
                    let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
                    let n1 = a_assigned.num_limbs();
                    let ab = bigint_chip.square(ctx, &a_assigned)?;
                    let ans_big = BigUint::from(23224568931658367244754058218082222889u128)
                        + BigUint::from_str("88516562921839445888640380379840781596").unwrap()
                            * &out_base
                        + BigUint::from_str("194478888615417946406783868151393774738").unwrap()
                            * &out_base.pow(2)
                        + BigUint::from_str("382395265476432217957523230769986571504").unwrap()
                            * &out_base.pow(3)
                        + BigUint::from_str("575971019676008360859069855433378813941").unwrap()
                            * &out_base.pow(4)
                        + BigUint::from_str("670174995752918677131397897218932582682").unwrap()
                            * &out_base.pow(5)
                        + BigUint::from_str("780239872348808029089572423614905198300").unwrap()
                            * &out_base.pow(6)
                        + BigUint::from_str("850410093737715640261630122959874522628").unwrap()
                            * &out_base.pow(7)
                        + BigUint::from_str("800314959349304909735238452892956199392").unwrap()
                            * &out_base.pow(8)
                        + BigUint::from_str("906862855407309870283714027678210238070").unwrap()
                            * &out_base.pow(9)
                        + BigUint::from_str("967727310654811444144097720329196927129").unwrap()
                            * &out_base.pow(10)
                        + BigUint::from_str("825671020037461535758117365587238596380").unwrap()
                            * &out_base.pow(11)
                        + BigUint::from_str("991281789723902700168027417052185830252").unwrap()
                            * &out_base.pow(12)
                        + BigUint::from_str("1259367815833216292413970809061165585320").unwrap()
                            * &out_base.pow(13)
                        + BigUint::from_str("1351495628781923848799708082622582598675").unwrap()
                            * &out_base.pow(14)
                        + BigUint::from_str("1451028634949220760698564802414695011932").unwrap()
                            * &out_base.pow(15)
                        + BigUint::from_str("1290756126635958771067082204577975256756").unwrap()
                            * &out_base.pow(16)
                        + BigUint::from_str("936482288980049848345464202850902738826").unwrap()
                            * &out_base.pow(17)
                        + BigUint::from_str("886330568585033438612679243731110283692").unwrap()
                            * &out_base.pow(18)
                        + BigUint::from_str("823948310509772835433730556487356331346").unwrap()
                            * &out_base.pow(19)
                        + BigUint::from_str("649341353489205691855914543942648985328").unwrap()
                            * &out_base.pow(20)
                        + BigUint::from_str("497838205323760437611385487609464464168").unwrap()
                            * &out_base.pow(21)
                        + BigUint::from_str("430091148520710550273018448938020664564").unwrap()
                            * &out_base.pow(22)
                        + BigUint::from_str("474098876922017329965321439330710234148").unwrap()
                            * &out_base.pow(23)
                        + BigUint::from_str("536697574159375092388958994084813127393").unwrap()
                            * &out_base.pow(24)
                        + BigUint::from_str("483446024935732188792400155524449880972").unwrap()
                            * &out_base.pow(25)
                        + BigUint::from_str("289799562463011227421662267162524920264").unwrap()
                            * &out_base.pow(26)
                        + BigUint::from_str("104372664369829937912234314161010649544").unwrap()
                            * &out_base.pow(27)
                        + BigUint::from_str("18130279752377737976455635841349605284").unwrap()
                            * &out_base.pow(28)
                        + BigUint::from_str("7809007931264072381739139035072").unwrap()
                            * &out_base.pow(29)
                        + BigUint::from_str("840867892083599894415616").unwrap()
                            * &out_base.pow(30)
                        + BigUint::from_str("0").unwrap() * &out_base.pow(31);
                    let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n1)?;
                    bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n1)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase6Circuit,
        test_mul_case6,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "(1+x)(1+x+x^2) =  1 + 2x + 2x^2 + x^3",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
                    let a_big = BigUint::from(1usize) + 1usize * &out_base;
                    let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
                    let n1 = a_assigned.num_limbs();
                    let b_big =
                        BigUint::from(1usize) + 1usize * &out_base + 1usize * &out_base.pow(2);
                    let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
                    let n2 = b_assigned.num_limbs();
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let ans_big = BigUint::from(1usize)
                        + 2usize * &out_base
                        + 2usize * &out_base.pow(2u32)
                        + 1usize * &out_base.pow(3u32);
                    let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n2)?;
                    bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n2)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase7Circuit,
        test_mul_case7,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "(1+7x)(1+x+x^2) =  1 + 8x + 8x^2 + 7x^3",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
                    let a_big = BigUint::from(1usize) + 7usize * &out_base;
                    let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
                    let n1 = a_assigned.num_limbs();
                    let b_big =
                        BigUint::from(1usize) + 1usize * &out_base + 1usize * &out_base.pow(2);
                    let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
                    let n2 = b_assigned.num_limbs();
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let ans_big = BigUint::from(1usize)
                        + 8usize * &out_base
                        + 8usize * &out_base.pow(2u32)
                        + 7usize * &out_base.pow(3u32);
                    let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n2)?;
                    bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n2)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModCase1Circuit,
        test_mulmod_case1,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "0 * (random) = 0 mod n",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let zero_big = BigUint::from(0usize);
                    let a_big = zero_big.clone();
                    let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let ans_big = zero_big;
                    let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &ans_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModCase2Circuit,
        test_mulmod_case2,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "n * 1 mod n = 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_big = BigUint::from(1usize);
                    let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let ans_big = BigUint::from(0usize);
                    let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &ans_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModCase3Circuit,
        test_mulmod_case3,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "(n - 1) * (n - 1) mod n = 1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let n_sub_1 = &self.n - &1u8;
                    let a_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let ans_big = BigUint::from(1usize);
                    let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &ans_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModCase4Circuit,
        test_mulmod_case4,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "(n - 1) * (n - 2) mod n = 2",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let n_sub_1 = &self.n - &1u8;
                    let a_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let n_sub_2 = &self.n - &2u8;
                    let b_limbs = decompose_big::<F>(n_sub_2.clone(), num_limbs, Self::LIMB_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
                    let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let ans_big = BigUint::from(2usize);
                    let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab, &ans_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestDeriveTraitsCircuit,
        test_derive_traits,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "test derive traits",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let bigint_chip = bigint_chip.clone();
                    format!("{bigint_chip:?}");
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let a_assigned = a_assigned.clone();
                    format!("{a_assigned:?}");
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            //range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestUnimplemented,
        test_unimplemented_circuit,
        64,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            Ok(())
        }
    );

    #[test]
    #[should_panic]
    fn test_unimplemented() {
        use halo2wrong::curves::bn256::Fq;
        let a = BigUint::default();
        let b = BigUint::default();
        let n = BigUint::default();
        let circuit = TestUnimplemented::<Fq> {
            a,
            b,
            n,
            _f: PhantomData,
        };
        circuit.without_witnesses();
    }
}
