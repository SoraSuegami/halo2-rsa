use std::marker::PhantomData;

use super::utils::{decompose_bigint, decompose_biguint};
use crate::{
    AssignedBigInt, BigIntInstructions, CarryModParams, Fresh, Muled, RangeType, RefreshAux,
};
use halo2_base::halo2_proofs::{circuit::Region, circuit::Value, plonk::Error};
use halo2_base::utils::fe_to_bigint;
use halo2_base::ContextParams;
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context,
};
use halo2_ecc::bigint::{
    big_is_equal, big_is_zero, big_less_than, carry_mod, mul_no_carry, select, sub, CRTInteger,
    FixedCRTInteger, FixedOverflowInteger, OverflowInteger,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed};

#[derive(Clone, Debug)]
pub struct BigIntConfig<F: PrimeField> {
    pub range: RangeConfig<F>,
    pub limb_bits: usize,
}

impl<F: PrimeField> BigIntInstructions<F> for BigIntConfig<F> {
    fn assign_integer<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        value: Value<BigUint>,
        bit_len: usize,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        assert_eq!(bit_len % self.limb_bits, 0);
        let num_limbs = bit_len / self.limb_bits;
        let gate = self.gate();
        let range = self.range();
        let limbs = value
            .as_ref()
            .map(|v| decompose_biguint(v, num_limbs, self.limb_bits))
            .transpose_vec(num_limbs);
        let limbs = limbs
            .into_iter()
            .map(|v| QuantumCell::Witness(v))
            .collect::<Vec<QuantumCell<F>>>();
        let assigned_limbs: Vec<AssignedValue<F>> = gate.assign_region(ctx, limbs, vec![]);
        for limb in assigned_limbs.iter() {
            range.range_check(ctx, &limb, self.limb_bits);
        }
        let int = OverflowInteger::construct(assigned_limbs, self.limb_bits);
        Ok(AssignedBigInt::new(int, value))
    }

    fn assign_constant<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        value: BigUint,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let num_limbs = self.num_limbs(&BigInt::from_biguint(Sign::Plus, value.clone()));
        let limbs = decompose_biguint::<F>(&value, num_limbs, self.limb_bits);
        let fixed_int = FixedOverflowInteger::construct(limbs);
        let int = fixed_int.assign(self.gate(), ctx, self.limb_bits);
        Ok(AssignedBigInt::new(int, Value::known(value)))
    }

    fn max_value<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        num_limbs: usize,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let value = BigUint::from(1u64) << (self.limb_bits * num_limbs);
        self.assign_constant(ctx, value)
    }

    fn refresh<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Muled>,
        aux: &RefreshAux,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        // For converting `a` to a [`Fresh`] type integer, we decompose each limb of `a` into `self.limb_width`-bits values.
        assert_eq!(self.limb_bits, aux.limb_bits);
        // The i-th value of `aux.increased_limbs_vec` represents the number of increased values when converting i-th limb of `a` into `self.limb_width`-bits values.
        let increased_limbs_vec = aux.increased_limbs_vec.clone();
        let num_limbs_l = aux.num_limbs_l;
        let num_limbs_r = aux.num_limbs_r;
        // The following assertion holds since `a` is the product of two integers `l` and `r` whose number of limbs is `num_limbs_l` and `num_limbs_r`, respectively.
        assert_eq!(a.num_limbs(), num_limbs_l + num_limbs_r - 1);
        let num_limbs_fresh = increased_limbs_vec.len();

        let gate = self.gate();
        let mut refreshed_limbs = Vec::with_capacity(num_limbs_fresh);
        let zero_assigned = gate.load_zero(ctx);
        let a_limbs = a.limbs();
        for i in 0..a.num_limbs() {
            refreshed_limbs.push(a_limbs[i].clone());
        }
        for _ in 0..(num_limbs_fresh - a.num_limbs()) {
            refreshed_limbs.push(zero_assigned.clone());
        }
        let limb_max = BigInt::from(1u64) << self.limb_bits;
        for i in 0..num_limbs_fresh {
            // `i`-th overflowing limb value.
            let mut limb = refreshed_limbs[i].clone();
            for j in 0..(increased_limbs_vec[i] + 1) {
                // `n` is lower `self.limb_width` bits of `limb`.
                // `q` is any other upper bits.
                let (q, n) = self.div_mod_unsafe(ctx, &limb, &limb_max);
                if j == 0 {
                    // When `j=0`, `n` is a new `i`-th limb value.
                    refreshed_limbs[i] = n;
                } else {
                    // When `j>0`, `n` is carried to the `i+j`-th limb.
                    refreshed_limbs[i + j] = gate.add(
                        ctx,
                        QuantumCell::Existing(&refreshed_limbs[i + j]),
                        QuantumCell::Existing(&n),
                    );
                }
                // We use `q` as the next `limb`.
                limb = q;
            }
            // `limb` should be zero because we decomposed all bits of the `i`-th overflowing limb value into `self.limb_width` bits values.
            gate.assert_is_const(ctx, &limb, F::zero());
        }
        let range = self.range();
        for limb in refreshed_limbs.iter() {
            range.range_check(ctx, &limb, self.limb_bits);
        }
        let int = OverflowInteger::construct(refreshed_limbs, self.limb_bits);
        // refreshed_value.map(|v| println!("refreshed_value {:?}", v));
        // a.value().map(|v| println!("a {:?}", v));
        let new_assigned_int = AssignedBigInt::new(int, a.value());
        // let new_assigned_int_muled = new_assigned_int.to_muled();
        // let is_eq = self.is_equal_muled(
        //     ctx,
        //     &a,
        //     &new_assigned_int_muled,
        //     aux.num_limbs_l,
        //     aux.num_limbs_r,
        // )?;
        // gate.assert_is_const(ctx, &is_eq, F::one());
        // let new_assigned_int = new_assigned_int_muled.to_fresh_unsafe();
        Ok(new_assigned_int)
        // let p = self.compute_max_mul(num_limbs_l, num_limbs_r);
        // let new_num_limbs = self.num_limbs(&p) + 10;
        // let gate = self.gate();
        // let zero_value = gate.load_zero(ctx);
        // let a = a.extend_limbs(new_num_limbs - a.num_limbs(), zero_value);
        // let carry_mod_params = CarryModParams::<F>::new(self.limb_bits, new_num_limbs, p);
        // Ok(AssignedBigInt::new(self.carry_mod(
        //     ctx,
        //     &a.crt,
        //     carry_mod_params,
        // )))
    }

    /// Given a bit value `sel`, return `a` if `a`=1 and `b` otherwise.
    fn select<'v, T: RangeType>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, T>,
        b: &AssignedBigInt<'v, F, T>,
        sel: &AssignedValue<'v, F>,
    ) -> Result<AssignedBigInt<'v, F, T>, Error> {
        let int = select::assign(self.gate(), ctx, &a.int, &b.int, sel);
        let value = a
            .value
            .as_ref()
            .zip(b.value.as_ref())
            .zip(sel.value)
            .map(|((a, b), sel)| {
                if sel == F::one() {
                    a.clone()
                } else {
                    b.clone()
                }
            });
        Ok(AssignedBigInt::new(int, value))
    }

    /// Given two inputs `a,b`, performs the addition `a + b`.
    fn add<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let gate = self.gate();
        let range = self.range();
        let out_value = a.value.as_ref().zip(b.value.as_ref()).map(|(a, b)| a + b);
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        let max_n = if n1 < n2 { n2 } else { n1 };
        let zero_value = gate.load_zero(ctx);
        let a = a.extend_limbs(max_n - n1, zero_value.clone());
        let b = b.extend_limbs(max_n - n2, zero_value.clone());

        // Compute a sum and a carry for each limb values.
        let mut c_vals = Vec::with_capacity(max_n);
        let mut carrys = Vec::with_capacity(max_n + 1);
        carrys.push(zero_value);
        let limb_max = BigUint::from(1usize) << self.limb_bits;
        let limb_max_f = biguint_to_fe(&limb_max);
        for i in 0..max_n {
            let a_b = gate.add(
                ctx,
                QuantumCell::Existing(a.limb(i)),
                QuantumCell::Existing(b.limb(i)),
            );
            let sum = gate.add(
                ctx,
                QuantumCell::Existing(&a_b),
                QuantumCell::Existing(&carrys[i]),
            );
            let sum_big = sum.value().map(|f| fe_to_biguint(f));
            // `c_val_f` is lower `self.limb_bits` bits of `a + b + carrys[i]`.
            let c_val: Value<F> = sum_big
                .clone()
                .map(|b| biguint_to_fe::<F>(&(&b % &limb_max)));
            let carry_val: Value<F> = sum_big.map(|b| biguint_to_fe::<F>(&(b >> self.limb_bits)));
            // `c` and `carry` should fit in `self.limb_bits` bits.
            let c = gate.load_witness(ctx, c_val);
            range.range_check(ctx, &c, self.limb_bits);
            let carry = gate.load_witness(ctx, carry_val);
            range.range_check(ctx, &carry, self.limb_bits);
            let c_add_carry = gate.mul_add(
                ctx,
                QuantumCell::Existing(&carry),
                QuantumCell::Constant(limb_max_f),
                QuantumCell::Existing(&c),
            );
            // `a + b + carrys[i] == c + carry`
            gate.assert_equal(
                ctx,
                QuantumCell::Existing(&sum),
                QuantumCell::Existing(&c_add_carry),
            );
            c_vals.push(c);
            carrys.push(carry);
        }
        // Add the last carry to the `c_vals`.
        c_vals.push(carrys[max_n].clone());
        let int = OverflowInteger::construct(c_vals, self.limb_bits);
        Ok(AssignedBigInt::new(int, out_value))
    }

    /// Given two inputs `a,b`, performs the subtraction `a - b`.
    // returns (a-b, underflow), where underflow is nonzero iff a < b
    fn sub<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<(AssignedBigInt<'v, F, Fresh>, AssignedValue<'v, F>), Error> {
        let gate = self.gate();
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        let max_n = if n1 < n2 { n2 } else { n1 };
        let zero_value = gate.load_zero(ctx);
        let a = a.extend_limbs(max_n - n1, zero_value.clone());
        let b = b.extend_limbs(max_n - n2, zero_value.clone());
        let limb_base = biguint_to_fe::<F>(&(BigUint::one() << self.limb_bits));
        let (int, overflow) =
            sub::assign(self.range(), ctx, &a.int, &b.int, self.limb_bits, limb_base);
        let value = a.value.zip(b.value).map(|(a, b)| a - b);
        Ok((AssignedBigInt::new(int, value), overflow))
    }

    fn mul<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Muled>, Error> {
        let gate = self.gate();
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        let num_limbs = n1 + n2 - 1;
        let zero_value = gate.load_zero(ctx);
        let a = a.extend_limbs(num_limbs - n1, zero_value.clone());
        let b = b.extend_limbs(num_limbs - n2, zero_value.clone());
        let num_limbs_log2_ceil = (num_limbs as f32).log2().ceil() as usize;
        let int = mul_no_carry::truncate(self.gate(), ctx, &a.int, &b.int, num_limbs_log2_ceil);
        let value = a.value.zip(b.value).map(|(a, b)| a * b);
        Ok(AssignedBigInt::new(int, value))
    }

    fn square<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Muled>, Error> {
        self.mul(ctx, a, a)
    }

    /// Given two inputs `a,b` and a modulus `n`, performs the modular addition `a + b mod n`.
    fn add_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        // 1. Compute `a + b`.
        // 2. Compute `a + b - n`.
        // 3. If the subtraction is overflowed, i.e., `a + b < n`, returns `a + b`. Otherwise, returns `a + b - n`.
        let added = self.add(ctx, a, b)?;
        // The number of limbs of `subed` is `added.num_limbs() = max(a.num_limbs(), b.num_limbs()) + 1`.
        let (subed, overflow) = self.sub(ctx, &added, n)?;
        let gate = self.gate();
        let is_overflow_zero = gate.is_zero(ctx, &overflow);
        let result = self.select(ctx, &subed, &added, &is_overflow_zero)?;
        Ok(result)
    }

    /// Given two inputs `a,b` and a modulus `n`, performs the modular subtraction `a - b mod n`.
    fn sub_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        // 1. Compute `a - b`.
        // 2. Compute `n + (a - b)`.
        // 3. If the subtraction in 1 is overflowed, i.e., `a - b < 0`, returns `a - b + n`. Otherwise, returns `a - b`.
        // The number of limbs of `subed1` is `max(a.num_limbs(), b.num_limbs())`.
        let (subed, overflow) = self.sub(ctx, a, b)?;
        let added = self.add(ctx, n, &subed)?;
        let gate = self.gate();
        let is_overflow_zero = gate.is_zero(ctx, &overflow);
        let result = self.select(ctx, &subed, &added, &is_overflow_zero)?;
        Ok(result)
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
    fn mul_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        // The following constraints are designed with reference to AsymmetricMultiplierReducer template in https://github.com/jacksoom/circom-bigint/blob/master/circuits/mult.circom.
        // However, we do not regroup multiple limbs like the circom-bigint implementation because addition is not free, i.e., it makes constraints as well as multiplication, in the Plonk constraints system.
        // Besides, we use lookup tables to optimize range checks.
        let limb_bits = self.limb_bits;
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        assert_eq!(n1, n.num_limbs());
        let (a_big, b_big, n_big) = (a.value(), b.value(), n.value());
        // 1. Compute the product as `BigUint`.
        let full_prod_big = a_big * b_big;
        // 2. Compute the quotient and remainder when the product is divided by `n`.
        let (q_big, prod_big) = full_prod_big
            .zip(n_big.as_ref())
            .map(|(full_prod, n)| (&full_prod / n, &full_prod % n))
            .unzip();

        // 3. Assign the quotient and remainder after checking the range of each limb.
        let assign_q = self.assign_integer(ctx, q_big, n2 * limb_bits)?;
        let assign_n = self.assign_integer(ctx, n_big, n1 * limb_bits)?;
        let assign_prod = self.assign_integer(ctx, prod_big, n1 * limb_bits)?;
        // 4. Assert `a * b = quotient_int * n + prod_int`, i.e., `prod_int = (a * b) mod n`.
        let ab = self.mul(ctx, a, b)?;
        let qn = self.mul(ctx, &assign_q, &assign_n)?;
        let gate = self.gate();
        let n_sum = n1 + n2;
        let qn_prod = {
            let value = qn
                .value
                .as_ref()
                .zip(assign_prod.value.as_ref())
                .map(|(a, b)| a + b);
            let mut limbs = Vec::with_capacity(n1 + n2 - 1);
            let qn_limbs = qn.limbs();
            let prod_limbs = assign_prod.limbs();
            for i in 0..(n_sum - 1) {
                if i < n1 {
                    limbs.push(gate.add(
                        ctx,
                        QuantumCell::Existing(&qn_limbs[i]),
                        QuantumCell::Existing(&prod_limbs[i]),
                    ));
                } else {
                    limbs.push(qn_limbs[i].clone());
                }
            }
            let int = OverflowInteger::construct(limbs, self.limb_bits);
            AssignedBigInt::<F, Muled>::new(int, value)
        };
        let is_eq = self.is_equal_muled(ctx, &ab, &qn_prod, n1, n2)?;
        gate.assert_is_const(ctx, &is_eq, F::one());
        Ok(assign_prod)
    }

    /// Given a input `a` and a modulus `n`, performs the modular square `a^2 mod n`.
    fn square_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        self.mul_mod(ctx, a, a, n)
    }

    /// Given a base `a`, a variable exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        e: &AssignedValue<'v, F>,
        n: &AssignedBigInt<'v, F, Fresh>,
        exp_bits: usize,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let gate = self.gate();
        let e_bits = gate.num_to_bits(ctx, e, exp_bits);
        let num_limbs = a.num_limbs();
        assert_eq!(num_limbs, n.num_limbs());
        let mut acc = self.assign_constant(ctx, BigUint::one())?;
        let zero = gate.load_zero(ctx);
        acc = acc.extend_limbs(num_limbs - acc.num_limbs(), zero);
        let mut squared = a.clone();
        for e_bit in e_bits.into_iter() {
            // Compute `acc * squared`.
            let muled = self.mul_mod(ctx, &acc, &squared, n)?;
            // If `e_bit = 1`, update `acc` to `acc * squared`. Otherwise, use the same `acc`.
            acc = self.select(ctx, &muled, &acc, &e_bit)?;
            // Square `squared`.
            squared = self.square_mod(ctx, &squared, n)?;
        }
        Ok(acc)
    }

    /// Given a base `a`, a fixed exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod_fixed_exp<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        e: &BigUint,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let num_limbs = a.num_limbs();
        assert_eq!(num_limbs, n.num_limbs());
        let num_e_bits = Self::bits_size(&BigInt::from_biguint(Sign::Plus, e.clone()));
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
        let mut acc = self.assign_constant(ctx, BigUint::from(1usize))?;
        let zero = self.gate().load_zero(ctx);
        acc = acc.extend_limbs(num_limbs - acc.num_limbs(), zero);
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
    fn is_zero<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &'v AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        let out = big_is_zero::assign(self.gate(), ctx, a.int_ref());
        Ok(out)
    }

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn is_equal_fresh<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        Ok(big_is_equal::assign(self.gate(), ctx, &a.int, &b.int))
    }

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn is_equal_muled<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Muled>,
        b: &AssignedBigInt<'v, F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedValue<'v, F>, Error> {
        // let a = self.refresh(ctx, a, num_limbs_l, num_limbs_r)?;
        // let b = self.refresh(ctx, b, num_limbs_l, num_limbs_r)?;
        // self.is_equal_fresh(ctx, &a, &b)
        // The following constraints are designed with reference to EqualWhenCarried template in https://github.com/jacksoom/circom-bigint/blob/master/circuits/mult.circom.
        // We use lookup tables to optimize range checks.
        let min_n = if num_limbs_r >= num_limbs_l {
            num_limbs_l
        } else {
            num_limbs_r
        };
        // Each limb of `a` and `b` is less than `min_n * (1^(limb_bits) - 1)^2  + (1^(limb_bits) - 1)`.
        let muled_limb_max = Self::compute_muled_limb_max(self.limb_bits, min_n);
        let muled_limb_max_fe = bigint_to_fe::<F>(&muled_limb_max);
        let num_limbs = num_limbs_l + num_limbs_r - 1;
        let muled_limb_max_bits = Self::bits_size(&(&muled_limb_max * 2u32));
        let carry_bits = muled_limb_max_bits - self.limb_bits;
        let gate = self.gate();
        let range = self.range();

        // The naive approach is to subtract the two integers limb by limb and:
        //  a. Verify that they sum to zero along the way while
        //  b. Propagating carries
        // but this doesn't work because early sums might be negative.
        // So instead we verify that `a - b + word_max = word_max`.
        let limb_max = BigInt::from(1) << self.limb_bits;
        let zero = gate.load_constant(ctx, F::zero());
        let mut accumulated_extra = zero.clone();
        let mut carry = Vec::with_capacity(num_limbs);
        let mut cs = Vec::with_capacity(num_limbs);
        carry.push(zero.clone());
        let mut eq_bit = gate.load_constant(ctx, F::one());
        let a_limbs = a.limbs();
        let b_limbs = b.limbs();
        for i in 0..num_limbs {
            // `sum = a - b + word_max`
            let a_b_sub = gate.sub(
                ctx,
                QuantumCell::Existing(&a_limbs[i]),
                QuantumCell::Existing(&b_limbs[i]),
            );
            let sum = gate.sum(
                ctx,
                vec![
                    QuantumCell::Existing(&a_b_sub),
                    QuantumCell::Existing(&carry[i]),
                    QuantumCell::Constant(muled_limb_max_fe),
                ],
            );
            // `c` is lower `self.limb_width` bits of `sum`.
            // `new_carry` is any other upper bits.
            let (new_carry, c) = self.div_mod_unsafe(ctx, &sum, &limb_max);
            carry.push(new_carry);
            cs.push(c);

            // `accumulated_extra` is the sum of `word_max`.
            accumulated_extra = gate.add(
                ctx,
                QuantumCell::Existing(&accumulated_extra),
                QuantumCell::Constant(muled_limb_max_fe),
            );
            let (q_acc, mod_acc) = self.div_mod_unsafe(ctx, &accumulated_extra, &limb_max);
            // If and only if `a` is equal to `b`, lower `self.limb_width` bits of `sum` and `accumulated_extra` are the same.
            let cs_acc_eq = gate.is_equal(
                ctx,
                QuantumCell::Existing(&cs[i]),
                QuantumCell::Existing(&mod_acc),
            );
            eq_bit = gate.and(
                ctx,
                QuantumCell::Existing(&eq_bit),
                QuantumCell::Existing(&cs_acc_eq),
            );
            accumulated_extra = q_acc;
            // accumulated_extra
            //     .value
            //     .map(|v| println!("accumulated_extra {:?}", v));

            if i < num_limbs - 1 {
                // Assert that each carry fits in `carry_bits` bits.
                range.range_check(ctx, &carry[i + 1], carry_bits);
            } else {
                // The final carry should match the `accumulated_extra`.
                let final_carry_eq = gate.is_equal(
                    ctx,
                    QuantumCell::Existing(&carry[i + 1]),
                    QuantumCell::Existing(&accumulated_extra),
                );
                eq_bit = gate.and(
                    ctx,
                    QuantumCell::Existing(&eq_bit),
                    QuantumCell::Existing(&final_carry_eq),
                );
            }
        }
        Ok(eq_bit)
    }

    /// Returns an assigned bit representing whether `a` is less than `b` (`a<b`).
    fn is_less_than<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        let (_, overflow) = self.sub(ctx, a, b)?;
        let gate = self.gate();
        let is_overflow_zero = gate.is_zero(ctx, &overflow);
        let is_overfloe = gate.not(ctx, QuantumCell::Existing(&is_overflow_zero));
        Ok(is_overfloe)
    }

    /// Returns an assigned bit representing whether `a` is less than or equal to `b` (`a<=b`).
    fn is_less_than_or_equal<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        let is_less = self.is_less_than(ctx, a, b)?;
        let is_eq = self.is_equal_fresh(ctx, a, b)?;
        let gate = self.gate();
        let is_not_eq = gate.not(ctx, QuantumCell::Existing(&is_eq));
        Ok(gate.and(
            ctx,
            QuantumCell::Existing(&is_less),
            QuantumCell::Existing(&is_not_eq),
        ))
    }

    /// Returns an assigned bit representing whether `a` is greater than `b` (`a>b`).
    fn is_greater_than<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        let is_less_than_or_eq = self.is_less_than_or_equal(ctx, a, b)?;
        Ok(self
            .gate()
            .not(ctx, QuantumCell::Existing(&is_less_than_or_eq)))
    }

    /// Returns an assigned bit representing whether `a` is greater than or equal to `b` (`a>=b`).
    fn is_greater_than_or_equal<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        let is_less_than = self.is_less_than(ctx, a, b)?;
        Ok(self.gate().not(ctx, QuantumCell::Existing(&is_less_than)))
    }

    /// Returns an assigned bit representing whether `a` is in the order-`n` finite field.
    fn is_in_field<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        self.is_less_than(ctx, a, n)
    }

    /// Assert that an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn assert_equal_fresh<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<(), Error> {
        let result = self.is_equal_fresh(ctx, a, b)?;
        self.gate().assert_is_const(ctx, &result, F::one());
        Ok(())
    }

    /// Assert that an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn assert_equal_muled<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Muled>,
        b: &AssignedBigInt<'v, F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<(), Error> {
        let result = self.is_equal_muled(ctx, a, b, num_limbs_l, num_limbs_r)?;
        self.gate().assert_is_const(ctx, &result, F::one());
        Ok(())
    }

    /// Assert that an assigned bit representing whether `a` is in the order-`n` finite field.
    fn assert_in_field<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<(), Error> {
        let result = self.is_in_field(ctx, a, b)?;
        self.gate().assert_is_const(ctx, &result, F::one());
        Ok(())
    }
}

impl<F: PrimeField> BigIntConfig<F> {
    /// Construct a new [`BigIntChip`] from the configuration and parameters.
    ///
    /// # Arguments
    ///
    /// # Return values
    /// Returns a new [`BigIntChip`]
    pub fn construct(range: RangeConfig<F>, limb_bits: usize) -> Self {
        Self { range, limb_bits }
    }

    /// Getter for [`RangeConfig`].
    pub fn range(&self) -> &RangeConfig<F> {
        &self.range
    }

    /// Getter for [`FlexGateConfig`].
    pub fn gate(&self) -> &FlexGateConfig<F> {
        &self.range.gate
    }

    pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
        Context::new(
            region,
            ContextParams {
                max_rows: self.range.gate.max_rows,
                num_context_ids: 1,
                fixed_columns: self.range.gate.constants.clone(),
            },
        )
    }

    /// Returns the fewest bits necessary to express the [`BigUint`].
    fn bits_size(val: &BigInt) -> usize {
        val.bits() as usize
    }

    fn num_limbs(&self, val: &BigInt) -> usize {
        let bits = Self::bits_size(&val);
        let num_limbs = if bits % self.limb_bits == 0 {
            bits / self.limb_bits
        } else {
            bits / self.limb_bits + 1
        };
        num_limbs
    }

    fn native_modulus_uint() -> BigUint {
        modulus::<F>()
    }

    fn native_modulus_int() -> BigInt {
        BigInt::from_biguint(Sign::Plus, modulus::<F>())
    }

    // /// Returns the maximum limb size of [`Muled`] type integers.
    // fn compute_mul_word_max(limb_width: usize, min_n: usize) -> BigUint {
    //     let one = BigUint::from(1usize);
    //     let out_base = BigUint::from(1usize) << limb_width;
    //     BigUint::from(min_n) * (&out_base - &one) * (&out_base - &one) + (&out_base - &one)
    // }

    fn compute_max_mul(&self, num_limbs_l: usize, num_limbs_r: usize) -> BigInt {
        // let one = BigInt::from(1u64);
        // let l_max = &(BigInt::from(1u64) << (self.limb_bits * num_limbs_l)) - &one;
        // let r_max = &(BigInt::from(1u64) << (self.limb_bits * num_limbs_r)) - &one;
        // l_max * r_max + one
        BigInt::from(1u64) << (self.limb_bits * (num_limbs_l + num_limbs_r))
    }

    /// Returns the maximum limb size of [`Muled`] type integers.
    fn compute_muled_limb_max(limb_width: usize, min_n: usize) -> BigInt {
        let one = BigInt::from(1usize);
        let out_base = BigInt::from(1usize) << limb_width;
        BigInt::from(min_n) * (&out_base - &one) * (&out_base - &one) + (&out_base - &one)
    }

    /// Given a integer `a` and a divisor `n`, performs `a/n` and `a mod n`.
    /// # Panics
    /// Panics if `n=0`.
    fn div_mod_unsafe<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedValue<'v, F>,
        b: &BigInt,
    ) -> (AssignedValue<'v, F>, AssignedValue<'v, F>) {
        let gate = self.gate();
        let (q_val, n_val) = a
            .value
            .map(|a| {
                let a = fe_to_bigint(&a);
                let (q_val, n_val) = (&a / b, &a % b);
                (bigint_to_fe(&q_val), bigint_to_fe(&n_val))
            })
            .unzip();
        let q = gate.load_witness(ctx, q_val);
        let n = gate.load_witness(ctx, n_val);
        let prod = gate.mul(
            ctx,
            QuantumCell::Existing(&q),
            QuantumCell::Constant(bigint_to_fe(b)),
        );
        let a_prod_sub = gate.sub(ctx, QuantumCell::Existing(&a), QuantumCell::Existing(&prod));
        let is_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&n),
            QuantumCell::Existing(&a_prod_sub),
        );
        gate.assert_is_const(ctx, &is_eq, F::one());
        (q, n)
    }

    // fn carry_mod<'v>(
    //     &self,
    //     ctx: &mut Context<'v, F>,
    //     a: &CRTInteger<'v, F>,
    //     carry_mod_params: CarryModParams<F>,
    // ) -> CRTInteger<'v, F> {
    //     carry_mod::crt(
    //         self.range(),
    //         ctx,
    //         &a,
    //         carry_mod_params.num_limbs_bits,
    //         &carry_mod_params.p,
    //         &carry_mod_params.p_limbs,
    //         carry_mod_params.p_native,
    //         carry_mod_params.limb_bits,
    //         &carry_mod_params.limb_bases,
    //         &carry_mod_params.limb_base_big,
    //     )
    // }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::big_pow_mod;
    use halo2_base::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
    use num_traits::FromPrimitive;

    macro_rules! impl_bigint_test_circuit {
        ($circuit_name:ident, $test_fn_name:ident, $limb_width:expr, $bits_len:expr, $k:expr, $should_be_error:expr, $( $synth:tt )*) => {
            struct $circuit_name<F: PrimeField> {
                a: BigUint,
                b: BigUint,
                n: BigUint,
                _f: PhantomData<F>,
            }

            impl<F: PrimeField> $circuit_name<F> {
                const LIMB_WIDTH: usize = $limb_width;
                const BITS_LEN: usize = $bits_len;
                const NUM_ADVICE:usize = 50;
                const NUM_FIXED:usize = 1;
                const NUM_LOOKUP_ADVICE:usize = 4;
                const LOOKUP_BITS:usize = 12;
            }

            impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
                type Config = BigIntConfig<F>;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let range_config = RangeConfig::configure(meta,Vertical, &[Self::NUM_ADVICE], &[Self::NUM_LOOKUP_ADVICE], Self::NUM_FIXED, Self::LOOKUP_BITS, 0, $k);
                    let bigint_config = BigIntConfig::construct(range_config, Self::LIMB_WIDTH);
                    bigint_config
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                use num_bigint::RandomBits;
                use rand::{thread_rng, Rng};
                fn run<F: PrimeField>() {
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

                    let public_inputs = vec![];
                    let k = $k;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    prover.verify().unwrap();
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }
                run::<Fr>();
            }
        };
    }

    impl_bigint_test_circuit!(
        TestAddCircuit,
        test_add_circuit,
        64,
        2048,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random add test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let a_assigned =
                        config.assign_integer(ctx, Value::known(self.a.clone()), Self::BITS_LEN)?;
                    let b_assigned =
                        config.assign_integer(ctx, Value::known(self.b.clone()), Self::BITS_LEN)?;
                    let ab = config.add(ctx, &a_assigned, &b_assigned)?;
                    let ba = config.add(ctx, &b_assigned, &a_assigned)?;
                    config.assert_equal_fresh(ctx, &ab, &ba)?;
                    config.range().finalize(ctx);
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                        let const_rows = ctx.total_fixed + 1;
                        println!("maximum rows used by a fixed column: {const_rows}");
                        println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    // impl_bigint_test_circuit!(
    //     TestButAddCircuit,
    //     test_but_add_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random add test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let added = bigint_chip.add(ctx, &a_assigned, &b_assigned)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &a_assigned, &added)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestSubCircuit,
    //     test_sub_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random sub test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let b: BigUint = &self.b >> 8;
    //                 let sub = &self.a - &b;
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let sub_assigned_int = bigint_chip.assign_constant_fresh(ctx, sub)?;
    //                 let (subed, is_overflowed) = bigint_chip.sub(ctx, &a_assigned, &b_assigned)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &sub_assigned_int, &subed)?;
    //                 bigint_chip.main_gate().assert_zero(ctx, &is_overflowed)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestOverflowSubCircuit,
    //     test_overflow_sub_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random sub test with an overflow case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = &self.a >> 1024;
    //                 let b: BigUint = self.b.clone();
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let (_, is_overflowed) = bigint_chip.sub(ctx, &a_assigned, &b_assigned)?;
    //                 bigint_chip.main_gate().assert_one(ctx, &is_overflowed)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadSubCircuit,
    //     test_bad_sub_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random sub test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let b: BigUint = &self.b >> 8;
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
    //                 let (subed, _) = bigint_chip.sub(ctx, &a_assigned, &b_assigned)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &zero, &subed)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    impl_bigint_test_circuit!(
        TestMulCircuit,
        test_mul_circuit,
        64,
        2048,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random mul test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let a_assigned =
                        config.assign_integer(ctx, Value::known(self.a.clone()), Self::BITS_LEN)?;
                    let b_assigned =
                        config.assign_integer(ctx, Value::known(self.b.clone()), Self::BITS_LEN)?;
                    config.mul(ctx, &a_assigned, &b_assigned)?;
                    config.range().finalize(ctx);
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                        let const_rows = ctx.total_fixed + 1;
                        println!("maximum rows used by a fixed column: {const_rows}");
                        println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    // impl_bigint_test_circuit!(
    //     TestBadMuledEqualCircuit,
    //     test_bad_muled_equal_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_equal_muled test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 assert!(self.a != BigUint::from(0usize));
    //                 assert!(self.b != BigUint::from(0usize));
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
    //                 let zero = bigint_chip.assign_constant_muled(
    //                     ctx,
    //                     BigUint::from(0usize),
    //                     num_limbs,
    //                     num_limbs,
    //                 )?;
    //                 bigint_chip.assert_equal_muled(
    //                     ctx,
    //                     &ab,
    //                     &zero,
    //                     a_assigned.num_limbs(),
    //                     b_assigned.num_limbs(),
    //                 )?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    impl_bigint_test_circuit!(
        TestFreshEqualCircuit,
        test_fresh_equal_circuit,
        64,
        2048,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random add test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let a_assigned =
                        config.assign_integer(ctx, Value::known(self.a.clone()), Self::BITS_LEN)?;
                    let b_assigned =
                        config.assign_integer(ctx, Value::known(self.b.clone()), Self::BITS_LEN)?;
                    config.assert_equal_fresh(ctx, &a_assigned, &a_assigned)?;
                    config.assert_equal_fresh(ctx, &b_assigned, &b_assigned)?;
                    config.range().finalize(ctx);
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                        let const_rows = ctx.total_fixed + 1;
                        println!("maximum rows used by a fixed column: {const_rows}");
                        println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    // impl_bigint_test_circuit!(
    //     TestBadFreshEqualCircuit,
    //     test_bad_fresh_equal_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_equal_fresh test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 assert!(self.a != BigUint::from(0usize));
    //                 let a1_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a1_unassigned = UnassignedInteger::from(a1_limbs);
    //                 let a1_assigned = bigint_chip.assign_integer(ctx, a1_unassigned)?;
    //                 let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
    //                 bigint_chip.assert_equal_fresh(ctx, &a1_assigned, &zero)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    impl_bigint_test_circuit!(
        TestMuledEqualCircuit,
        test_muled_equal_circuit,
        64,
        2048,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random refresh test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let a_assigned =
                        config.assign_integer(ctx, Value::known(self.a.clone()), Self::BITS_LEN)?;
                    let b_assigned =
                        config.assign_integer(ctx, Value::known(self.b.clone()), Self::BITS_LEN)?;
                    let ab = config.mul(ctx, &a_assigned, &b_assigned)?;
                    let ba = config.mul(ctx, &b_assigned, &a_assigned)?;
                    let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
                    config.assert_equal_muled(ctx, &ab, &ba, num_limbs, num_limbs)?;
                    config.range().finalize(ctx);
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                        let const_rows = ctx.total_fixed + 1;
                        println!("maximum rows used by a fixed column: {const_rows}");
                        println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestRefreshCircuit,
        test_refresh_circuit,
        64,
        2048,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random refresh test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let a_assigned =
                        config.assign_integer(ctx, Value::known(self.a.clone()), Self::BITS_LEN)?;
                    let b_assigned =
                        config.assign_integer(ctx, Value::known(self.b.clone()), Self::BITS_LEN)?;
                    let ab = config.mul(ctx, &a_assigned, &b_assigned)?;
                    let ba = config.mul(ctx, &b_assigned, &a_assigned)?;
                    let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
                    let aux = RefreshAux::new(Self::LIMB_WIDTH, num_limbs, num_limbs);
                    let ab_refreshed = config.refresh(ctx, &ab, &aux)?;
                    let ba_refreshed = config.refresh(ctx, &ba, &aux)?;
                    config.assert_equal_fresh(ctx, &ab_refreshed, &ba_refreshed)?;
                    config.range().finalize(ctx);
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                        let const_rows = ctx.total_fixed + 1;
                        println!("maximum rows used by a fixed column: {const_rows}");
                        println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestThreeMulCircuit,
        test_three_mul_circuit,
        64,
        2048,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random mul test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let a_assigned =
                        config.assign_integer(ctx, Value::known(self.a.clone()), Self::BITS_LEN)?;
                    let b_assigned =
                        config.assign_integer(ctx, Value::known(self.b.clone()), Self::BITS_LEN)?;
                    let n_assigned =
                        config.assign_integer(ctx, Value::known(self.n.clone()), Self::BITS_LEN)?;
                    let ab = config.mul(ctx, &a_assigned, &b_assigned)?;
                    let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
                    let aux = RefreshAux::new(Self::LIMB_WIDTH, num_limbs, num_limbs);
                    let ab_refreshed = config.refresh(ctx, &ab, &aux)?;
                    let abn = config.mul(ctx, &ab_refreshed, &n_assigned)?;
                    let nb = config.mul(ctx, &n_assigned, &b_assigned)?;
                    let nb_refreshed = config.refresh(ctx, &nb, &aux)?;
                    let nba = config.mul(ctx, &nb_refreshed, &a_assigned)?;
                    // [TODO] Error in the assert_equal_muled.
                    config.assert_equal_muled(ctx, &abn, &nba, num_limbs, num_limbs)?;
                    config.range().finalize(ctx);
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                        let const_rows = ctx.total_fixed + 1;
                        println!("maximum rows used by a fixed column: {const_rows}");
                        println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    // impl_bigint_test_circuit!(
    //     TestAddModCircuit,
    //     test_add_mod_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random add_mod test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.add_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 let ba = bigint_chip.add_mod(ctx, &b_assigned, &a_assigned, &n_assigned)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &ba)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadAddModCircuit,
    //     test_bad_add_mod_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random add_mod test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.add_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &n_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestSubModCircuit,
    //     test_sub_mod_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random sub_mod test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let sub = if &self.a >= &self.b {
    //                     &self.a - &self.b
    //                 } else {
    //                     &self.a + &self.n - &self.b
    //                 };
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.sub_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 let sub_assigned = bigint_chip.assign_constant_fresh(ctx, sub)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &sub_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestSubModOverflowCircuit,
    //     test_sub_mod_overflow_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random sub_mod overflow test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let n_limbs =
    //                     decompose_big::<F>(self.n.clone() >> 1024, num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 bigint_chip.sub_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadSubModCircuit,
    //     test_bad_sub_mod_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random sub_mod test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.sub_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &n_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    impl_bigint_test_circuit!(
        TestMulModCircuit,
        test_mul_mod_circuit,
        64,
        2048,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random refresh test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let a_assigned =
                        config.assign_integer(ctx, Value::known(self.a.clone()), Self::BITS_LEN)?;
                    let b_assigned =
                        config.assign_integer(ctx, Value::known(self.b.clone()), Self::BITS_LEN)?;
                    let n_assigned =
                        config.assign_integer(ctx, Value::known(self.n.clone()), Self::BITS_LEN)?;
                    let ab = config.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let ba = config.mul_mod(ctx, &b_assigned, &a_assigned, &n_assigned)?;
                    let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
                    let is_eq = config.is_equal_fresh(ctx, &ab, &ba)?;
                    config.gate().assert_is_const(ctx, &is_eq, F::one());
                    config.range().finalize(ctx);
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                        let const_rows = ctx.total_fixed + 1;
                        println!("maximum rows used by a fixed column: {const_rows}");
                        println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    // impl_bigint_test_circuit!(
    //     TestMulModEqualCircuit,
    //     test_module_mul_equal_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random mul_mod test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 let ba = bigint_chip.mul_mod(ctx, &b_assigned, &a_assigned, &n_assigned)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &ba)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadMulModEqualCircuit,
    //     test_bad_module_mul_equal_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random mul_mod test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &n_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestPowModCircuit,
    //     test_pow_mod_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random pow_mod test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let e_bit = 5;
    //                 let e: BigUint =
    //                     self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let e_assigned = bigint_chip.assign_constant(ctx, e.clone(), 1)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let powed =
    //                     bigint_chip.pow_mod(ctx, &a_assigned, &e_assigned, &n_assigned, e_bit)?;
    //                 let ans_big = big_pow_mod(&self.a, &e, &self.n);
    //                 let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &powed, &ans_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadPowModCircuit,
    //     test_bad_pow_mod_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random pow_mod test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let e_bit = 5;
    //                 let e: BigUint =
    //                     self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let e_assigned = bigint_chip.assign_constant(ctx, e.clone(), 1)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let powed =
    //                     bigint_chip.pow_mod(ctx, &a_assigned, &e_assigned, &n_assigned, e_bit)?;
    //                 let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
    //                 bigint_chip.assert_equal_fresh(ctx, &powed, &zero)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    impl_bigint_test_circuit!(
        TestPowModFixedExpCircuit,
        test_pow_mod_fixed_exp_circuit,
        64,
        2048,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random pow_mod test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let a_assigned =
                        config.assign_integer(ctx, Value::known(self.a.clone()), Self::BITS_LEN)?;
                    let n_assigned =
                        config.assign_integer(ctx, Value::known(self.n.clone()), Self::BITS_LEN)?;
                    let e = BigUint::from_u64(65537).unwrap();
                    let powed = config.pow_mod_fixed_exp(ctx, &a_assigned, &e, &n_assigned)?;
                    // let ans_big =
                    //     big_pow_mod(&self.a, &BigInt::from_biguint(Sign::Plus, e), &self.n);
                    // let ans_assigned = config.assign_constant(ctx, ans_big)?;
                    // let is_eq = config.is_equal_fresh(ctx, &powed, &ans_assigned)?;
                    // let gate = config.gate();
                    // gate.assert_is_const(ctx, &is_eq, F::one());
                    config.range().finalize(ctx);
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                        let const_rows = ctx.total_fixed + 1;
                        println!("maximum rows used by a fixed column: {const_rows}");
                        println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    // impl_bigint_test_circuit!(
    //     TestPowModFixedExpCircuit,
    //     test_pow_mod_fixed_exp_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random pow_mod test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let e_bit = 7;
    //                 let e: BigUint =
    //                     self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let powed = bigint_chip.pow_mod_fixed_exp(ctx, &a_assigned, &e, &n_assigned)?;
    //                 let ans_big = big_pow_mod(&self.a, &e, &self.n);
    //                 let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &powed, &ans_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadPowModFixedExpCircuit,
    //     test_bad_pow_mod_fixed_exp_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random pow_mod test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let e_bit = 7;
    //                 let e: BigUint =
    //                     self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let powed = bigint_chip.pow_mod_fixed_exp(ctx, &a_assigned, &e, &n_assigned)?;
    //                 let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
    //                 bigint_chip.assert_equal_fresh(ctx, &powed, &zero)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestIsZeroCircuit,
    //     test_is_zero_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random is_zero test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 assert!(self.a != BigUint::from(0usize));
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
    //                 bigint_chip.assert_zero(ctx, &zero)?;
    //                 let a_is_zero = bigint_chip.is_zero(ctx, &a_assigned)?;
    //                 let main_gate = bigint_chip.main_gate();
    //                 main_gate.assert_zero(ctx, &a_is_zero)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestLessThanCircuit,
    //     test_less_than_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_less_than test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = &self.a >> 128;
    //                 let b = self.b.clone();
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 bigint_chip.assert_less_than(ctx, &a_assigned, &b_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadLessThanCircuit,
    //     test_bad_less_than_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_less_than test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = self.a.clone();
    //                 let b = self.b.clone() >> 128;
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 bigint_chip.assert_less_than(ctx, &a_assigned, &b_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestLessThanOrEqualCircuit,
    //     test_less_than_or_equal_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_less_than_or_equal test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = self.a.clone();
    //                 let b = self.a.clone();
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 bigint_chip.assert_less_than_or_equal(ctx, &a_assigned, &b_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadLessThanOrEqualCircuit,
    //     test_bad_less_than_or_equal_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_less_than_or_equal test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = self.a.clone();
    //                 let b = self.b.clone() >> 128;
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 bigint_chip.assert_less_than_or_equal(ctx, &a_assigned, &b_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestGreaterThanCircuit,
    //     test_greater_than_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_greater_than test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = self.a.clone();
    //                 let b = self.a.clone() >> 128;
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 bigint_chip.assert_greater_than(ctx, &a_assigned, &b_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadGreaterThanCircuit,
    //     test_bad_greater_than_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_greater_than test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = self.a.clone() >> 128;
    //                 let b = self.b.clone();
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 bigint_chip.assert_greater_than(ctx, &a_assigned, &b_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestGreaterThanOrEqualCircuit,
    //     test_greater_than_or_equal_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_greater_than_or_equal test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = self.a.clone();
    //                 let b = self.a.clone();
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 bigint_chip.assert_greater_than_or_equal(ctx, &a_assigned, &b_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadGreaterThanOrEqualCircuit,
    //     test_bad_greater_than_or_equal_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_greater_than_or_equal test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a = self.a.clone() >> 128;
    //                 let b = self.b.clone();
    //                 let a_limbs = decompose_big::<F>(a, num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(b, num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 bigint_chip.assert_greater_than_or_equal(ctx, &a_assigned, &b_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestInFieldCircuit,
    //     test_in_field_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_in_field test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 bigint_chip.assert_in_field(ctx, &a_assigned, &n_assigned)?;
    //                 let zero = bigint_chip.assign_constant_fresh(ctx, BigUint::from(0usize))?;
    //                 bigint_chip.assert_in_field(ctx, &zero, &n_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestBadInFieldCircuit,
    //     test_bad_in_field_circuit,
    //     64,
    //     2048,
    //     true,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "random assert_in_field test with an error case",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 bigint_chip.assert_in_field(ctx, &n_assigned, &n_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulCase1Circuit,
    //     test_mul_case1,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         layouter.assign_region(
    //             || "1 * 1 = 1",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let one = bigint_chip.assign_constant_fresh(ctx, BigUint::from(1usize))?;
    //                 let n = one.num_limbs();
    //                 let one_muled = bigint_chip.mul(ctx, &one, &one)?;
    //                 let zero = AssignedLimb::from(
    //                     bigint_chip.main_gate().assign_constant(ctx, F::zero())?,
    //                 );
    //                 bigint_chip.assert_equal_muled(ctx, &one.to_muled(zero), &one_muled, n, n)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulCase3Circuit,
    //     test_mul_case3,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         layouter.assign_region(
    //             || "(1+0x+3x^2)(3+1x) = 3+1x+9x^2+3x^3",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
    //                 let a_big =
    //                     BigUint::from(1usize) + 0usize * &out_base + 3usize * &out_base * &out_base;
    //                 let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
    //                 let n1 = a_assigned.num_limbs();
    //                 let b_big =
    //                     BigUint::from(3usize) + 1usize * &out_base + 0usize * &out_base * &out_base;
    //                 let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
    //                 let n2 = b_assigned.num_limbs();
    //                 let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
    //                 let ans_big = BigUint::from(3usize)
    //                     + 1usize * &out_base
    //                     + 9usize * &out_base * &out_base
    //                     + 3usize * &out_base * &out_base * &out_base;
    //                 let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n2)?;
    //                 bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n2)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulCase4Circuit,
    //     test_mul_case4,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         layouter.assign_region(
    //             || "(3 + 4x + 5x^2 + 6x^3)(9 + 10x + 11x^2 + 12x^3) =  27 + 66 x  + 118 x^2 + 184 x^3 + 163 x^4 + 126 x^5 + 72 x^6 ",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
    //                 let a_big =
    //                     BigUint::from(3usize) + 4usize * &out_base + 5usize * &out_base.pow(2) + 6usize * &out_base.pow(3);
    //                 let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
    //                 let n1 = a_assigned.num_limbs();
    //                 let b_big =
    //                     BigUint::from(9usize) + 10usize * &out_base + 11usize * &out_base.pow(2) + 12usize * &out_base.pow(3);
    //                 let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
    //                 let n2 = b_assigned.num_limbs();
    //                 let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
    //                 let ans_big = BigUint::from(27usize) + 66usize * &out_base + 118usize * &out_base.pow(2u32) + 184usize * &out_base.pow(3u32) + 163usize * &out_base.pow(4u32) + 126usize * &out_base.pow(5u32) + 72usize * &out_base.pow(6u32);
    //                 let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n2)?;
    //                 bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n2)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulCase5Circuit,
    //     test_mul_case5,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         layouter.assign_region(
    //             || "big square test",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
    //                 let a_big = BigUint::from(4819187580044832333u128)
    //                     + 9183764011217009606u128 * &out_base
    //                     + 11426964127496009747u128 * &out_base.pow(2)
    //                     + 17898263845095661790u128 * &out_base.pow(3)
    //                     + 12102522037140783322u128 * &out_base.pow(4)
    //                     + 4029304176671511763u128 * &out_base.pow(5)
    //                     + 11339410859987005436u128 * &out_base.pow(6)
    //                     + 12120243430436644729u128 * &out_base.pow(7)
    //                     + 2888435820322958146u128 * &out_base.pow(8)
    //                     + 7612614626488966390u128 * &out_base.pow(9)
    //                     + 3872170484348249672u128 * &out_base.pow(10)
    //                     + 9589147526444685354u128 * &out_base.pow(11)
    //                     + 16391157694429928307u128 * &out_base.pow(12)
    //                     + 12256166884204507566u128 * &out_base.pow(13)
    //                     + 4257963982333550934u128 * &out_base.pow(14)
    //                     + 916988490704u128 * &out_base.pow(15);
    //                 let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
    //                 let n1 = a_assigned.num_limbs();
    //                 let ab = bigint_chip.square(ctx, &a_assigned)?;
    //                 let ans_big = BigUint::from(23224568931658367244754058218082222889u128)
    //                     + BigUint::from_str("88516562921839445888640380379840781596").unwrap()
    //                         * &out_base
    //                     + BigUint::from_str("194478888615417946406783868151393774738").unwrap()
    //                         * &out_base.pow(2)
    //                     + BigUint::from_str("382395265476432217957523230769986571504").unwrap()
    //                         * &out_base.pow(3)
    //                     + BigUint::from_str("575971019676008360859069855433378813941").unwrap()
    //                         * &out_base.pow(4)
    //                     + BigUint::from_str("670174995752918677131397897218932582682").unwrap()
    //                         * &out_base.pow(5)
    //                     + BigUint::from_str("780239872348808029089572423614905198300").unwrap()
    //                         * &out_base.pow(6)
    //                     + BigUint::from_str("850410093737715640261630122959874522628").unwrap()
    //                         * &out_base.pow(7)
    //                     + BigUint::from_str("800314959349304909735238452892956199392").unwrap()
    //                         * &out_base.pow(8)
    //                     + BigUint::from_str("906862855407309870283714027678210238070").unwrap()
    //                         * &out_base.pow(9)
    //                     + BigUint::from_str("967727310654811444144097720329196927129").unwrap()
    //                         * &out_base.pow(10)
    //                     + BigUint::from_str("825671020037461535758117365587238596380").unwrap()
    //                         * &out_base.pow(11)
    //                     + BigUint::from_str("991281789723902700168027417052185830252").unwrap()
    //                         * &out_base.pow(12)
    //                     + BigUint::from_str("1259367815833216292413970809061165585320").unwrap()
    //                         * &out_base.pow(13)
    //                     + BigUint::from_str("1351495628781923848799708082622582598675").unwrap()
    //                         * &out_base.pow(14)
    //                     + BigUint::from_str("1451028634949220760698564802414695011932").unwrap()
    //                         * &out_base.pow(15)
    //                     + BigUint::from_str("1290756126635958771067082204577975256756").unwrap()
    //                         * &out_base.pow(16)
    //                     + BigUint::from_str("936482288980049848345464202850902738826").unwrap()
    //                         * &out_base.pow(17)
    //                     + BigUint::from_str("886330568585033438612679243731110283692").unwrap()
    //                         * &out_base.pow(18)
    //                     + BigUint::from_str("823948310509772835433730556487356331346").unwrap()
    //                         * &out_base.pow(19)
    //                     + BigUint::from_str("649341353489205691855914543942648985328").unwrap()
    //                         * &out_base.pow(20)
    //                     + BigUint::from_str("497838205323760437611385487609464464168").unwrap()
    //                         * &out_base.pow(21)
    //                     + BigUint::from_str("430091148520710550273018448938020664564").unwrap()
    //                         * &out_base.pow(22)
    //                     + BigUint::from_str("474098876922017329965321439330710234148").unwrap()
    //                         * &out_base.pow(23)
    //                     + BigUint::from_str("536697574159375092388958994084813127393").unwrap()
    //                         * &out_base.pow(24)
    //                     + BigUint::from_str("483446024935732188792400155524449880972").unwrap()
    //                         * &out_base.pow(25)
    //                     + BigUint::from_str("289799562463011227421662267162524920264").unwrap()
    //                         * &out_base.pow(26)
    //                     + BigUint::from_str("104372664369829937912234314161010649544").unwrap()
    //                         * &out_base.pow(27)
    //                     + BigUint::from_str("18130279752377737976455635841349605284").unwrap()
    //                         * &out_base.pow(28)
    //                     + BigUint::from_str("7809007931264072381739139035072").unwrap()
    //                         * &out_base.pow(29)
    //                     + BigUint::from_str("840867892083599894415616").unwrap()
    //                         * &out_base.pow(30)
    //                     + BigUint::from_str("0").unwrap() * &out_base.pow(31);
    //                 let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n1)?;
    //                 bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n1)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulCase6Circuit,
    //     test_mul_case6,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         layouter.assign_region(
    //             || "(1+x)(1+x+x^2) =  1 + 2x + 2x^2 + x^3",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
    //                 let a_big = BigUint::from(1usize) + 1usize * &out_base;
    //                 let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
    //                 let n1 = a_assigned.num_limbs();
    //                 let b_big =
    //                     BigUint::from(1usize) + 1usize * &out_base + 1usize * &out_base.pow(2);
    //                 let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
    //                 let n2 = b_assigned.num_limbs();
    //                 let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
    //                 let ans_big = BigUint::from(1usize)
    //                     + 2usize * &out_base
    //                     + 2usize * &out_base.pow(2u32)
    //                     + 1usize * &out_base.pow(3u32);
    //                 let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n2)?;
    //                 bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n2)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulCase7Circuit,
    //     test_mul_case7,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         layouter.assign_region(
    //             || "(1+7x)(1+x+x^2) =  1 + 8x + 8x^2 + 7x^3",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let out_base = BigUint::from(1usize) << Self::LIMB_WIDTH;
    //                 let a_big = BigUint::from(1usize) + 7usize * &out_base;
    //                 let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
    //                 let n1 = a_assigned.num_limbs();
    //                 let b_big =
    //                     BigUint::from(1usize) + 1usize * &out_base + 1usize * &out_base.pow(2);
    //                 let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
    //                 let n2 = b_assigned.num_limbs();
    //                 let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
    //                 let ans_big = BigUint::from(1usize)
    //                     + 8usize * &out_base
    //                     + 8usize * &out_base.pow(2u32)
    //                     + 7usize * &out_base.pow(3u32);
    //                 let ans_assigned = bigint_chip.assign_constant_muled(ctx, ans_big, n1, n2)?;
    //                 bigint_chip.assert_equal_muled(ctx, &ab, &ans_assigned, n1, n2)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulModCase1Circuit,
    //     test_mulmod_case1,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "0 * (random) = 0 mod n",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let zero_big = BigUint::from(0usize);
    //                 let a_big = zero_big.clone();
    //                 let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
    //                 let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 let ans_big = zero_big;
    //                 let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &ans_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulModCase2Circuit,
    //     test_mulmod_case2,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "n * 1 mod n = 0",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_big = BigUint::from(1usize);
    //                 let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 let ans_big = BigUint::from(0usize);
    //                 let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &ans_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulModCase3Circuit,
    //     test_mulmod_case3,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "(n - 1) * (n - 1) mod n = 1",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let n_sub_1 = &self.n - &1u8;
    //                 let a_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let b_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 let ans_big = BigUint::from(1usize);
    //                 let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &ans_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestMulModCase4Circuit,
    //     test_mulmod_case4,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "(n - 1) * (n - 2) mod n = 2",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let n_sub_1 = &self.n - &1u8;
    //                 let a_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let n_sub_2 = &self.n - &2u8;
    //                 let b_limbs = decompose_big::<F>(n_sub_2.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let b_unassigned = UnassignedInteger::from(b_limbs);
    //                 let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
    //                 let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let n_unassigned = UnassignedInteger::from(n_limbs);
    //                 let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;
    //                 let ab = bigint_chip.mul_mod(ctx, &a_assigned, &b_assigned, &n_assigned)?;
    //                 let ans_big = BigUint::from(2usize);
    //                 let ans_assigned = bigint_chip.assign_constant_fresh(ctx, ans_big)?;
    //                 bigint_chip.assert_equal_fresh(ctx, &ab, &ans_assigned)?;
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestDeriveTraitsCircuit,
    //     test_derive_traits,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         let bigint_chip = self.bigint_chip(config);
    //         let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
    //         layouter.assign_region(
    //             || "test derive traits",
    //             |region| {
    //                 let offset = 0;
    //                 let ctx = &mut RegionCtx::new(region, offset);
    //                 let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::LIMB_WIDTH);
    //                 let a_unassigned = UnassignedInteger::from(a_limbs);
    //                 let bigint_chip = bigint_chip.clone();
    //                 format!("{bigint_chip:?}");
    //                 let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
    //                 let a_assigned = a_assigned.clone();
    //                 format!("{a_assigned:?}");
    //                 Ok(())
    //             },
    //         )?;
    //         let range_chip = bigint_chip.range_chip();
    //         range_chip.load_table(&mut layouter)?;
    //         //range_chip.load_overflow_tables(&mut layouter)?;
    //         Ok(())
    //     }
    // );

    // impl_bigint_test_circuit!(
    //     TestUnimplemented,
    //     test_unimplemented_circuit,
    //     64,
    //     2048,
    //     false,
    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    //     ) -> Result<(), Error> {
    //         Ok(())
    //     }
    // );

    // #[test]
    // #[should_panic]
    // fn test_unimplemented() {
    //     use halo2wrong::curves::bn256::Fq;
    //     let a = BigUint::default();
    //     let b = BigUint::default();
    //     let n = BigUint::default();
    //     let circuit = TestUnimplemented::<Fq> {
    //         a,
    //         b,
    //         n,
    //         _f: PhantomData,
    //     };
    //     circuit.without_witnesses();
    // }
}
