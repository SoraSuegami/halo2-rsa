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
    big_is_equal, big_is_zero, carry_mod, mul_no_carry, select, CRTInteger, FixedCRTInteger,
    OverflowInteger,
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
        let limbs = decompose_bigint_option(value.map(|v| &v), num_limbs, bit_len);
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
                value.map(|v| bigint_to_fe::<F>(&(&v % native_module))),
            )];
            gate.assign_region_last(ctx, native_cells, vec![])
        };
        let crt = CRTInteger::construct(truncation, assigned_native, value);
        Ok(AssignedBigInt::new(crt))
    }

    fn assign_constant(
        &self,
        ctx: &mut Context<'_, F>,
        value: BigUint,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
        let num_limbs = self.num_limbs(&BigInt::from_biguint(Sign::NoSign, value));
        let fixed_crt = FixedCRTInteger::from_native(value, num_limbs, self.limb_bits);
        let native_modulus = Self::native_modulus_uint();
        let crt = fixed_crt.assign(self.gate(), ctx, self.limb_bits, &native_modulus);
        Ok(AssignedBigInt::new(crt))
    }

    fn max_value(
        &self,
        ctx: &mut Context<'_, F>,
        num_limbs: usize,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
        let value = BigUint::from(1u64) << (self.limb_bits * num_limbs);
        self.assign_constant(ctx, value)
    }

    fn refresh(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
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
    fn select<T: RangeType>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, T>,
        b: &AssignedBigInt<F, T>,
        sel: &AssignedValue<F>,
    ) -> Result<AssignedBigInt<F, T>, Error> {
        let crt = select::crt(self.gate(), ctx, &a.crt, &b.crt, sel);
        Ok(AssignedBigInt::new(crt))
    }

    fn mul(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Fresh>,
        b: &AssignedBigInt<F, Fresh>,
    ) -> Result<AssignedBigInt<F, Muled>, Error> {
        let num_limbs = a.num_limbs() + b.num_limbs();
        let num_limbs_log2_ceil = (num_limbs as f32).log2().ceil() as usize;
        let crt = mul_no_carry::crt(self.gate(), ctx, &a.crt, &b.crt, num_limbs_log2_ceil);
        Ok(AssignedBigInt::new(crt))
    }

    fn square(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Fresh>,
    ) -> Result<AssignedBigInt<F, Muled>, Error> {
        self.mul(ctx, a, a)
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
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Fresh>,
        b: &AssignedBigInt<F, Fresh>,
        n: &AssignedBigInt<F, Fresh>,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
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
        let (mut q_big, mut prod_big) = full_prod_big
            .zip(n_big)
            .map(|(full_prod, n)| (&full_prod / &n, &full_prod % &n))
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
            let mut limbs = Vec::with_capacity(n1 + n2 - 1);
            let qn_limbs = qn.crt.truncation.limbs;
            let prod_limbs = assign_prod.crt.truncation.limbs;
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
            let out_crt = CRTInteger::construct(trunc, native, value);
            AssignedBigInt::<F, Muled>::new(out_crt)
        };
        let is_eq = self.is_equal_muled(ctx, &ab, &qn_prod, n1, n2)?;
        gate.assert_is_const(ctx, &is_eq, F::zero());
        Ok(assign_prod)
    }

    /// Given a input `a` and a modulus `n`, performs the modular square `a^2 mod n`.
    fn square_mod(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Fresh>,
        n: &AssignedBigInt<F, Fresh>,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
        self.mul_mod(ctx, a, a, n)
    }

    /// Given a base `a`, a variable exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Fresh>,
        e: &AssignedValue<F>,
        n: &AssignedBigInt<F, Fresh>,
        exp_bits: usize,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
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
    fn pow_mod_fixed_exp(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Fresh>,
        e: &BigUint,
        n: &AssignedBigInt<F, Fresh>,
    ) -> Result<AssignedBigInt<F, Fresh>, Error> {
        let num_e_bits = Self::bits_size(&BigInt::from_biguint(Sign::NoSign, *e));
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
    fn is_zero(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        Ok(big_is_zero::crt(self.gate(), ctx, &a.crt))
    }

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn is_equal_fresh(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Fresh>,
        b: &AssignedBigInt<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error> {
        Ok(big_is_equal::crt(self.gate(), ctx, &a.crt, &b.crt))
    }

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn is_equal_muled(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedBigInt<F, Muled>,
        b: &AssignedBigInt<F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let a = self.refresh(ctx, a, num_limbs_l, num_limbs_r)?;
        let b = self.refresh(ctx, b, num_limbs_l, num_limbs_r)?;
        self.is_equal_fresh(ctx, &a, &b)
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
        let l_max = (BigInt::from(1u64) << (self.limb_bits * num_limbs_l)) - one;
        let r_max = (BigInt::from(1u64) << (self.limb_bits * num_limbs_r)) - one;
        l_max * r_max + one
    }

    fn carry_mod(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        carry_mod_params: CarryModParams<F>,
    ) -> CRTInteger<F> {
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
