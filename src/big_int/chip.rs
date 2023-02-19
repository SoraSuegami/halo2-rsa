use std::marker::PhantomData;

use crate::{AssignedBigInt, BigIntInstructions, CarryModParams, Fresh, Muled, RangeType};

use halo2_base::halo2_proofs::{circuit::Value, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{
        bigint_to_fe, biguint_to_fe, bit_length, decompose_bigint_option, decompose_biguint,
        fe_to_biguint, modulus, PrimeField,
    },
    AssignedValue, Context,
};
use halo2_ecc::bigint::{
    big_is_equal, big_is_zero, big_less_than, carry_mod, mul_no_carry, select, sub, CRTInteger,
    FixedCRTInteger, OverflowInteger,
};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::One;

#[derive(Clone, Debug)]
pub struct BigUintConfig<F: PrimeField> {
    pub range: RangeConfig<F>,
    pub limb_bits: usize,
}

impl<F: PrimeField> BigIntInstructions<F> for BigUintConfig<F> {
    fn assign_uint(
        &self,
        ctx: &mut Context<'_, F>,
        value: Value<BigInt>,
        bit_len: usize,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
        assert_eq!(bit_len % self.limb_bits, 0);
        let num_limbs = bit_len / self.limb_bits;
        let gate = self.gate();
        let range = self.range();
        let limbs = decompose_bigint_option(value.as_ref(), num_limbs, bit_len);
        let limbs = limbs
            .into_iter()
            .map(|v| QuantumCell::Witness(v))
            .collect::<Vec<QuantumCell<F>>>();
        let assigned_limbs: Vec<AssignedValue<F>> = gate.assign_region(ctx, limbs, vec![]);
        for limb in assigned_limbs.iter() {
            range.range_check(ctx, &limb, self.limb_bits);
        }
        let truncation = OverflowInteger::construct(assigned_limbs, self.limb_bits);
        let native_module = Self::native_modulus_int();
        let assigned_native = {
            let native_cells = vec![QuantumCell::Witness(
                value
                    .as_ref()
                    .map(|v| bigint_to_fe::<F>(&(v % native_module))),
            )];
            gate.assign_region_last(ctx, native_cells, vec![])
        };
        let crt = CRTInteger::construct(truncation, assigned_native, value);
        Ok(AssignedBigInt::new(crt))
    }

    fn assign_constant<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        value: BigUint,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let num_limbs = self.num_limbs(&BigInt::from_biguint(Sign::NoSign, value.clone()));
        let fixed_crt = FixedCRTInteger::from_native(value, num_limbs, self.limb_bits);
        let native_modulus = Self::native_modulus_uint();
        let crt = fixed_crt.assign(self.gate(), ctx, self.limb_bits, &native_modulus);
        Ok(AssignedBigInt::new(crt))
    }

    fn max_value<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        num_limbs: usize,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let value = BigUint::from(1u64) << (self.limb_bits * num_limbs);
        self.assign_constant(ctx, value)
    }

    fn refresh<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let p = self.compute_max_mul(num_limbs_l, num_limbs_r);
        let num_limbs = self.num_limbs(&p);
        let carry_mod_params = CarryModParams::<F>::new(self.limb_bits, num_limbs, p);
        Ok(AssignedBigInt::new(self.carry_mod(
            ctx,
            &a.crt,
            carry_mod_params,
        )))
    }

    /// Given a bit value `sel`, return `a` if `a`=1 and `b` otherwise.
    fn select<'v, T: RangeType>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, T>,
        b: &AssignedBigInt<'v, F, T>,
        sel: &AssignedValue<'v, F>,
    ) -> Result<AssignedBigInt<'v, F, T>, Error> {
        let crt = select::crt(self.gate(), ctx, &a.crt, &b.crt, sel);
        Ok(AssignedBigInt::new(crt))
    }

    /// Given two inputs `a,b`, performs the addition `a + b`.
    fn add<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
        let gate = self.gate();
        let range = self.range();
        let out_native = gate.add(
            ctx,
            QuantumCell::Existing(&a.crt.native),
            QuantumCell::Existing(&b.crt.native),
        );
        let out_value = a
            .crt
            .value
            .as_ref()
            .zip(b.crt.value.as_ref())
            .map(|(a, b)| a + b);
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
        let out_trunc = OverflowInteger::construct(c_vals, self.limb_bits);
        let crt = CRTInteger::<'v, _>::construct(out_trunc, out_native, out_value);
        Ok(AssignedBigInt::new(crt))
    }

    /// Given two inputs `a,b`, performs the subtraction `a - b`.
    // returns (a-b, underflow), where underflow is nonzero iff a < b
    fn sub<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<(AssignedBigInt<'v, F, Fresh>, AssignedValue<F>), Error> {
        let gate = self.gate();
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        let max_n = if n1 < n2 { n2 } else { n1 };
        let zero_value = gate.load_zero(ctx);
        let a = a.extend_limbs(max_n - n1, zero_value.clone());
        let b = b.extend_limbs(max_n - n2, zero_value.clone());
        let limb_base = biguint_to_fe::<F>(&(BigUint::one() << self.limb_bits));
        let (crt, overflow) =
            sub::crt(self.range(), ctx, &a.crt, &b.crt, self.limb_bits, limb_base);
        Ok((AssignedBigInt::new(crt), overflow))
    }

    fn mul<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Muled>, Error> {
        let num_limbs = a.num_limbs() + b.num_limbs();
        let num_limbs_log2_ceil = (num_limbs as f32).log2().ceil() as usize;
        let crt = mul_no_carry::crt(self.gate(), ctx, &a.crt, &b.crt, num_limbs_log2_ceil);
        Ok(AssignedBigInt::new(crt))
    }

    fn square<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Muled>, Error> {
        self.mul(ctx, a, a)
    }

    /// Given two inputs `a,b` and a modulus `n`, performs the modular addition `a + b mod n`.
    fn add_mod<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        // 1. Compute `a + b`.
        // 2. Compute `a + b - n`.
        // 3. If the subtraction is overflowed, i.e., `a + b < n`, returns `a + b`. Otherwise, returns `a + b - n`.
        let mut added = self.add(ctx, a, b)?;
        // The number of limbs of `subed` is `added.num_limbs() = max(a.num_limbs(), b.num_limbs()) + 1`.
        let (subed, overflow) = self.sub(ctx, &added, n)?;
        let gate = self.gate();
        let is_overflow_zero = gate.is_zero(ctx, &overflow);
        let result = self.select(ctx, &subed, &added, &is_overflow_zero)?;
        Ok(result)
    }

    /// Given two inputs `a,b` and a modulus `n`, performs the modular subtraction `a - b mod n`.
    fn sub_mod<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        // 1. Compute `a - b`.
        // 2. Compute `n + (a - b)`.
        // 3. If the subtraction in 1 is overflowed, i.e., `a - b < 0`, returns `a - b + n`. Otherwise, returns `a - b`.
        // The number of limbs of `subed1` is `max(a.num_limbs(), b.num_limbs())`.
        let (mut subed, overflow) = self.sub(ctx, a, b)?;
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
        &'v self,
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
        let (a_big, b_big, n_big) = (a.big_int(), b.big_int(), n.big_int());
        // 1. Compute the product as `BigUint`.
        let full_prod_big = a_big * b_big;
        // 2. Compute the quotient and remainder when the product is divided by `n`.
        let (q_big, prod_big) = full_prod_big
            .zip(n_big.as_ref())
            .map(|(full_prod, n)| (&full_prod / n, &full_prod % n))
            .unzip();

        // 3. Assign the quotient and remainder after checking the range of each limb.
        let assign_q = self.assign_uint(ctx, q_big, n2 * limb_bits)?;
        let assign_n = self.assign_uint(ctx, n_big, n1 * limb_bits)?;
        let assign_prod = self.assign_uint(ctx, prod_big, n1 * limb_bits)?;

        // 4. Assert `a * b = quotient_int * n + prod_int`, i.e., `prod_int = (a * b) mod n`.
        let ab = self.mul(ctx, a, b)?;
        let qn = self.mul(ctx, &assign_q, &assign_n)?;
        let gate = self.gate();
        let qn_prod = {
            let native = gate.add(
                ctx,
                QuantumCell::Existing(&qn.crt.native),
                QuantumCell::Existing(&assign_prod.crt.native()),
            );
            let value = qn
                .crt
                .value
                .as_ref()
                .zip(assign_prod.crt.value.as_ref())
                .map(|(a, b)| a + b);
            let mut limbs = Vec::with_capacity(n1 + n2 - 1);
            let qn_limbs = qn.crt.truncation.limbs;
            let prod_limbs = &assign_prod.crt.truncation.limbs[..];
            for i in 0..limbs.len() {
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
            let trunc = OverflowInteger::construct(limbs, self.limb_bits);
            let out_crt = CRTInteger::construct(trunc, native, value);
            AssignedBigInt::<F, Muled>::new(out_crt)
        };
        let is_eq = self.is_equal_muled(ctx, &ab, &qn_prod, n1, n2)?;
        gate.assert_is_const(ctx, &is_eq, F::zero());
        Ok(assign_prod)
    }

    /// Given a input `a` and a modulus `n`, performs the modular square `a^2 mod n`.
    fn square_mod<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        self.mul_mod(ctx, a, a, n)
    }

    /// Given a base `a`, a variable exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        e: &AssignedValue<'v, F>,
        n: &AssignedBigInt<'v, F, Fresh>,
        exp_bits: usize,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let gate = self.gate();
        let e_bits = gate.num_to_bits(ctx, e, exp_bits);
        let mut acc = self.assign_constant(ctx, BigUint::one())?;
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
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        e: &BigUint,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedBigInt<'v, F, Fresh>, Error> {
        let num_e_bits = Self::bits_size(&BigInt::from_biguint(Sign::NoSign, e.clone()));
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
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &'v AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        let out = big_is_zero::crt(self.gate(), ctx, a.crt_ref());
        Ok(out)
    }

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn is_equal_fresh<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        Ok(big_is_equal::crt(self.gate(), ctx, &a.crt, &b.crt))
    }

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn is_equal_muled<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Muled>,
        b: &AssignedBigInt<'v, F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let a = self.refresh(ctx, a, num_limbs_l, num_limbs_r)?;
        let b = self.refresh(ctx, b, num_limbs_l, num_limbs_r)?;
        self.is_equal_fresh(ctx, &a, &b)
    }

    /// Returns an assigned bit representing whether `a` is less than `b` (`a<b`).
    fn is_less_than<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        let (_, overflow) = self.sub(ctx, a, b)?;
        let gate = self.gate();
        let is_overflow_zero = gate.is_zero(ctx, &overflow);
        let is_overfloe = gate.not(ctx, QuantumCell::Existing(&is_overflow_zero));
        Ok(is_overfloe)
    }

    /// Returns an assigned bit representing whether `a` is less than or equal to `b` (`a<=b`).
    fn is_less_than_or_equal<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
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
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        let is_less_than_or_eq = self.is_less_than_or_equal(ctx, a, b)?;
        Ok(self
            .gate()
            .not(ctx, QuantumCell::Existing(&is_less_than_or_eq)))
    }

    /// Returns an assigned bit representing whether `a` is greater than or equal to `b` (`a>=b`).
    fn is_greater_than_or_equal<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        b: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        let is_less_than = self.is_less_than(ctx, a, b)?;
        Ok(self.gate().not(ctx, QuantumCell::Existing(&is_less_than)))
    }

    /// Returns an assigned bit representing whether `a` is in the order-`n` finite field.
    fn is_in_field<'v>(
        &'v self,
        ctx: &mut Context<'v, F>,
        a: &AssignedBigInt<'v, F, Fresh>,
        n: &AssignedBigInt<'v, F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        self.is_less_than(ctx, a, n)
    }
}

impl<F: PrimeField> BigUintConfig<F> {
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
        BigInt::from_biguint(Sign::NoSign, modulus::<F>())
    }

    // /// Returns the maximum limb size of [`Muled`] type integers.
    // fn compute_mul_word_max(limb_width: usize, min_n: usize) -> BigUint {
    //     let one = BigUint::from(1usize);
    //     let out_base = BigUint::from(1usize) << limb_width;
    //     BigUint::from(min_n) * (&out_base - &one) * (&out_base - &one) + (&out_base - &one)
    // }

    fn compute_max_mul(&self, num_limbs_l: usize, num_limbs_r: usize) -> BigInt {
        let one = BigInt::from(1u64);
        let l_max = &(BigInt::from(1u64) << (self.limb_bits * num_limbs_l)) - &one;
        let r_max = &(BigInt::from(1u64) << (self.limb_bits * num_limbs_r)) - &one;
        l_max * r_max + one
    }

    fn carry_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &CRTInteger<'v, F>,
        carry_mod_params: CarryModParams<F>,
    ) -> CRTInteger<'v, F> {
        carry_mod::crt(
            self.range(),
            ctx,
            &a,
            carry_mod_params.num_limbs_bits,
            &carry_mod_params.p,
            &carry_mod_params.p_limbs,
            carry_mod_params.p_native,
            carry_mod_params.limb_bits,
            &carry_mod_params.limb_bases,
            &carry_mod_params.limb_base_big,
        )
    }
}
