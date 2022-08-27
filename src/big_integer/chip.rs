use std::marker::PhantomData;

use crate::{
    AssignedInteger, AssignedLimb, BigIntInstructions, Fresh, Muled, RangeType, UnassignedInteger,
};
use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value, plonk::Error};
use maingate::{
    big_to_fe, decompose_big, fe_to_big, modulus, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};

use num_bigint::BigUint;

/// Configuration for [`BigIntegerChip`]
#[derive(Clone, Debug)]
pub struct BigIntConfig {
    /// Configuration for [`RangeChip`]
    range_config: RangeConfig,
    /// Configuration for [`MainGate`]
    main_gate_config: MainGateConfig,
}

impl BigIntConfig {
    pub fn new(range_config: RangeConfig, main_gate_config: MainGateConfig) -> Self {
        Self {
            range_config,
            main_gate_config,
        }
    }
}

/// Chip for integer instructions
#[derive(Debug)]
pub struct BigIntChip<F: FieldExt> {
    /// Chip configuration
    config: BigIntConfig,
    out_width: usize,
    num_limbs: usize,
    _f: PhantomData<F>,
}

impl<F: FieldExt> BigIntInstructions<F> for BigIntChip<F> {
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: UnassignedInteger<F>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let range_gate = self.range_chip();
        let out_width = self.out_width;
        let num_limbs = integer.num_limbs();
        assert_eq!(num_limbs, self.num_limbs);
        let values = (0..num_limbs)
            .map(|i| {
                let limb = integer.limb(i);
                range_gate.assign(ctx, limb, Self::sublimb_bit_len(out_width), out_width)
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let limbs = values
            .into_iter()
            .map(|v| AssignedLimb::from(v))
            .collect::<Vec<AssignedLimb<F, Fresh>>>();
        Ok(self.new_assigned_integer(&limbs))
    }

    fn assign_constant_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        self.assign_constant(ctx, integer, self.num_limbs)
    }

    fn assign_constant_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
        n1: usize,
        n2: usize,
    ) -> Result<AssignedInteger<F, Muled>, Error> {
        self.assign_constant(ctx, integer, n1 + n2 - 1)
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Muled>, Error> {
        let d0 = a.num_limbs();
        let d1 = b.num_limbs();
        let d = d0 + d1 - 1;
        let main_gate = self.main_gate();
        let mut c_vals = Vec::new();
        for i in 0..d {
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

    fn mul_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let out_width = self.out_width;
        let n1 = a.num_limbs();
        let n2 = b.num_limbs();
        assert_eq!(n1, n.num_limbs());
        let (a_big, b_big, n_big) = (
            a.to_big_uint(out_width),
            b.to_big_uint(out_width),
            n.to_big_uint(out_width),
        );
        let full_prod_big = a_big * b_big;
        let (mut q_big, mut prod_big) = full_prod_big
            .zip(n_big)
            .map(|(full_prod, n)| (&full_prod / &n, &full_prod % &n))
            .unzip();
        let mut quotients = Vec::new();
        let mut prods = Vec::new();
        let out_base = BigUint::from(1usize) << out_width;
        for _ in 0..n2 {
            let q = q_big.as_ref().map(|q| q % &out_base);
            q_big = q_big.map(|q| q >> out_width);
            quotients.push(q.map(|b| big_to_fe::<F>(b)));
        }
        for _ in 0..n1 {
            let p = prod_big.as_ref().map(|p| p % &out_base);
            prod_big = prod_big.map(|p| p >> out_width);
            prods.push(p.map(|b| big_to_fe::<F>(b)));
        }
        prod_big.map(|b| assert_eq!(b, BigUint::default()));
        q_big.map(|b| assert_eq!(b, BigUint::default()));

        let range_chip = self.range_chip();
        let quotient_assigns = quotients
            .into_iter()
            .map(|q| range_chip.assign(ctx, q, Self::sublimb_bit_len(out_width), out_width))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let quotient_limbs = quotient_assigns
            .into_iter()
            .map(|v| AssignedLimb::<F, Fresh>::from(v))
            .collect::<Vec<AssignedLimb<_, _>>>();
        let prod_assigns = prods
            .into_iter()
            .map(|p| range_chip.assign(ctx, p, Self::sublimb_bit_len(out_width), out_width))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let prod_limbs = prod_assigns
            .into_iter()
            .map(|v| AssignedLimb::<F, Fresh>::from(v))
            .collect::<Vec<AssignedLimb<_, _>>>();
        let quotient_int = AssignedInteger::new(&quotient_limbs);
        let prod_int = AssignedInteger::new(&prod_limbs);
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
        //self.equal_when_carried_regroup(ctx, &eq_a, &eq_b, max_word, out_width, n - 1)?;
        self.assert_equal_muled(ctx, &eq_a, &eq_b, n1, n2)?;
        Ok(prod_int)
    }

    fn square_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        self.mul_mod(ctx, a, a, n)
    }

    fn pow_mod(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        e: &AssignedInteger<F, Fresh>,
        n: &AssignedInteger<F, Fresh>,
        exp_limb_bits: usize,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let main_gate = self.main_gate();
        let e_bits = e
            .limbs()
            .into_iter()
            .map(|limb| main_gate.to_bits(ctx, &limb.0, exp_limb_bits))
            .collect::<Result<Vec<Vec<AssignedValue<F>>>, Error>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<AssignedValue<F>>>();
        let mut acc = self.assign_constant_fresh(ctx, BigUint::from(1usize))?;
        let mut squared = a.clone();
        for e_bit in e_bits.into_iter() {
            let muled = self.mul_mod(ctx, &acc, &squared, n)?;
            for j in 0..acc.num_limbs() {
                let selected = main_gate.select(ctx, &muled.limb(j), &acc.limb(j), &e_bit)?;
                acc.0[j] = AssignedLimb::from(selected);
            }
            squared = self.square_mod(ctx, &squared, n)?;
        }
        Ok(acc)
    }

    fn pow_mod_fixed_exp(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        e: &BigUint,
        n: &AssignedInteger<F, Fresh>,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let num_e_bits = Self::bits_size(e);
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
        let mut acc = self.assign_constant_fresh(ctx, BigUint::from(1usize))?;
        let mut squared = a.clone();
        for e_bit in e_bits.into_iter() {
            let cur_sq = squared;
            squared = self.square_mod(ctx, &cur_sq, n)?;
            if !e_bit {
                continue;
            }
            acc = self.mul_mod(ctx, &acc, &cur_sq, n)?;
        }
        Ok(acc)
    }

    fn assert_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Fresh>,
        b: &AssignedInteger<F, Fresh>,
    ) -> Result<(), Error> {
        let out_width = self.out_width;
        let word_max = BigUint::from(1usize) << out_width;
        let num_chunk = a.num_limbs();
        assert_eq!(num_chunk, b.num_limbs());
        self.assert_equal(ctx, a, b, word_max, out_width, num_chunk)
    }

    fn assert_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, Muled>,
        b: &AssignedInteger<F, Muled>,
        n1: usize,
        n2: usize,
    ) -> Result<(), Error> {
        let min_n = if n2 >= n1 { n1 } else { n2 };
        let n = n1 + n2;
        let max_word = Self::compute_mul_word_max(self.out_width, min_n);
        self.assert_equal(ctx, a, b, max_word, self.out_width, n - 1)
    }
}

impl<F: FieldExt> BigIntChip<F> {
    const NUM_LOOKUP_LIMBS: usize = 8;

    /// Create new ['BigIntChip'] with the configuration
    pub fn new(config: BigIntConfig, out_width: usize, bits_len: usize) -> Self {
        assert_eq!(bits_len % out_width, 0);
        let num_limbs = bits_len / out_width;
        let max_word = Self::compute_mul_word_max(out_width, num_limbs);
        assert!(Self::bits_size(&max_word) <= F::NUM_BITS as usize);
        BigIntChip {
            config,
            out_width,
            num_limbs,
            _f: PhantomData,
        }
    }

    /// Getter for [`RangeChip`]
    pub fn range_chip(&self) -> RangeChip<F> {
        RangeChip::<F>::new(self.config.range_config.clone())
    }

    /// Getter for [`MainGate`]
    pub fn main_gate(&self) -> MainGate<F> {
        let main_gate_config = self.config.main_gate_config.clone();
        MainGate::<F>::new(main_gate_config)
    }

    /// Creates a new [`AssignedInteger`] from its limb representation
    pub(crate) fn new_assigned_integer<T: RangeType>(
        &self,
        limbs: &[AssignedLimb<F, T>],
    ) -> AssignedInteger<F, T> {
        AssignedInteger::new(limbs)
    }

    pub fn compute_range_lens(out_width: usize, num_limbs: usize) -> (Vec<usize>, Vec<usize>) {
        let out_comp_bit_len = out_width / BigIntChip::<F>::NUM_LOOKUP_LIMBS;
        let out_overflow_bit_len = out_width % out_comp_bit_len;
        let one = BigUint::from(1usize);
        let out_base = BigUint::from(1usize) << out_width;

        let fresh_word_max_width = (2u32 * &out_base).bits() as usize;
        let fresh_carry_bits = fresh_word_max_width - out_width;
        let fresh_carry_comp_bit_len = BigIntChip::<F>::sublimb_bit_len(fresh_carry_bits);
        let fresh_carry_overflow_bit_len = fresh_carry_bits % fresh_carry_comp_bit_len;

        let mul_word_max =
            BigUint::from(num_limbs) * (&out_base - &one) * (&out_base - &one) + (&out_base - &one);
        let mul_word_max_width = (&mul_word_max * 2u32).bits() as usize;
        let mul_carry_bits = mul_word_max_width - out_width;
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

    fn assign_constant<T: RangeType>(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
        max_num_limbs: usize,
    ) -> Result<AssignedInteger<F, T>, Error> {
        let out_width = self.out_width;
        let int_bits_size = Self::bits_size(&integer);
        let is_fit = int_bits_size % out_width == 0;
        let num_limbs = if is_fit {
            int_bits_size / out_width
        } else {
            int_bits_size / out_width + 1
        };
        assert!(num_limbs <= max_num_limbs);
        let limbs = decompose_big::<F>(integer, num_limbs, out_width);
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

    fn assert_equal<T: RangeType>(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedInteger<F, T>,
        b: &AssignedInteger<F, T>,
        word_max: BigUint,
        out_width: usize,
        num_chunk: usize,
    ) -> Result<(), Error> {
        let word_max_width = Self::bits_size(&(&word_max * 2u32));
        let carry_bits = word_max_width - out_width;
        let main_gate = self.main_gate();
        let range_chip = self.range_chip();
        let out_base = main_gate.assign_constant(ctx, F::from_u128(1 << out_width))?;
        let mut accumulated_extra = main_gate.assign_constant(ctx, F::zero())?;
        let mut carry = Vec::with_capacity(num_chunk);
        let mut cs = Vec::with_capacity(num_chunk);
        carry.push(main_gate.assign_constant(ctx, F::zero())?);
        for i in 0..num_chunk {
            let a_b = main_gate.sub(ctx, &a.limb(i), &b.limb(i))?;
            let sum =
                main_gate.add_with_constant(ctx, &a_b, &carry[i], big_to_fe(word_max.clone()))?;
            let (new_carry, c) = self.div_mod_main_gate(ctx, &sum, &out_base)?;
            carry.push(new_carry);
            cs.push(c);

            accumulated_extra =
                main_gate.add_constant(ctx, &accumulated_extra, big_to_fe(word_max.clone()))?;
            let (q_acc, mod_acc) = self.div_mod_main_gate(ctx, &accumulated_extra, &out_base)?;
            main_gate.assert_equal(ctx, &cs[i], &mod_acc)?;
            accumulated_extra = q_acc;

            if i < num_chunk - 1 {
                let carry_value = carry[i + 1].value().copied();
                let range_assigned = range_chip.assign(
                    ctx,
                    carry_value,
                    Self::sublimb_bit_len(carry_bits),
                    carry_bits,
                )?;
                main_gate.assert_equal(ctx, &carry[i + 1], &range_assigned)?;
            } else {
                // The final carry should match the extra
                main_gate.assert_equal(ctx, &carry[i + 1], &accumulated_extra)?;
            }
        }
        Ok(())
    }

    fn div_mod_main_gate(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
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

    fn bits_size(val: &BigUint) -> usize {
        val.bits() as usize
    }

    fn sublimb_bit_len(bit_len_limb: usize) -> usize {
        //assert!(bit_len_limb % Self::NUM_LOOKUP_LIMBS == 0);
        let val = bit_len_limb / Self::NUM_LOOKUP_LIMBS;
        if val == 0 {
            1
        } else {
            val
        }
    }

    fn compute_mul_word_max(out_width: usize, min_n: usize) -> BigUint {
        let one = BigUint::from(1usize);
        let out_base = BigUint::from(1usize) << out_width;
        BigUint::from(min_n) * (&out_base - &one) * (&out_base - &one) + (&out_base - &one)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use halo2wrong::halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };

    macro_rules! impl_bigint_test_circuit {
        ($circuit_name:ident, $test_fn_name:ident, $out_width:expr, $bits_len:expr, $( $synth:tt )*) => {
            #[derive(Clone, Debug)]
            struct $circuit_name<F: FieldExt> {
                a: BigUint,
                b: BigUint,
                n: BigUint,
                _f: PhantomData<F>,
            }

            impl<F: FieldExt> $circuit_name<F> {
                const OUT_WIDTH: usize = $out_width;
                const BITS_LEN: usize = $bits_len;
                fn bigint_chip(&self, config: BigIntConfig) -> BigIntChip<F> {
                    BigIntChip::new(config, Self::OUT_WIDTH, Self::BITS_LEN)
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
                            Self::OUT_WIDTH,
                            Self::BITS_LEN / Self::OUT_WIDTH,
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
                    let k = 15;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e),
                    };
                    assert_eq!(prover.verify(), Ok(()));
                }

                use halo2wrong::curves::bn256::Fq as BnFq;
                use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
                run::<BnFq>();
                //run::<PastaFp>();
                //run::<PastaFq>();
            }
        };
    }

    impl_bigint_test_circuit!(
        TestMulCircuit,
        test_mul_circuit,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "random mul test",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::OUT_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::OUT_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMuledEqualCircuit,
        test_muled_equal_circuit,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "random assert_equal_muled test",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::OUT_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::OUT_WIDTH);
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestFreshEqualCircuit,
        test_fresh_equal_circuit,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "random assert_equal_fresh test",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a1_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::OUT_WIDTH);
                    let a1_unassigned = UnassignedInteger::from(a1_limbs);
                    let a2_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::OUT_WIDTH);
                    let a2_unassigned = UnassignedInteger::from(a2_limbs);
                    let a1_assigned = bigint_chip.assign_integer(ctx, a1_unassigned)?;
                    let a2_assigned = bigint_chip.assign_integer(ctx, a2_unassigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &a1_assigned, &a2_assigned)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModEqualCircuit,
        test_module_mul_equal_circuit,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "random mul_mod test",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::OUT_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::OUT_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::OUT_WIDTH);
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestPowModCircuit,
        test_pow_mod_circuit,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "random pow_mod test",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::OUT_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let e_bit = 4;
                    let e: BigUint =
                        self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
                    //let e_limbs = decompose_big::<F>(e.clone(), num_limbs, Self::OUT_WIDTH);
                    //let e_unassigned = UnassignedInteger::from(e_limbs);
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::OUT_WIDTH);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let e_assigned = bigint_chip.assign_constant(ctx, e.clone(), 1)?;
                    //.assign_integer(ctx, e_unassigned)?;
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestPowModFixedExpCircuit,
        test_pow_mod_fixed_exp_circuit,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "random pow_mod test",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a_limbs = decompose_big::<F>(self.a.clone(), num_limbs, Self::OUT_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let e_bit = 6;
                    let e: BigUint =
                        self.b.clone() & ((BigUint::from(1usize) << e_bit) - BigUint::from(1usize));
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::OUT_WIDTH);
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    fn big_pow_mod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
        let one = BigUint::from(1usize);
        let two = BigUint::from(2usize);
        if b == &BigUint::default() {
            return one;
        }
        let is_odd = b % &two == one;
        let b = if is_odd { b - &one } else { b.clone() };
        let x = big_pow_mod(a, &(&b / &two), n);
        let x2 = (&x * &x) % n;
        if is_odd {
            (a * &x2) % n
        } else {
            x2
        }
    }

    impl_bigint_test_circuit!(
        TestMulCase1Circuit,
        test_mul_case1,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "1 * 1 = 1",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase3Circuit,
        test_mul_case3,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "(1+0x+3x^2)(3+1x) = 3+1x+9x^2+3x^3",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let out_base = BigUint::from(1usize) << Self::OUT_WIDTH;
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase4Circuit,
        test_mul_case4,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "(3 + 4x + 5x^2 + 6x^3)(9 + 10x + 11x^2 + 12x^3) =  27 + 66 x  + 118 x^2 + 184 x^3 + 163 x^4 + 126 x^5 + 72 x^6 ",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let out_base = BigUint::from(1usize) << Self::OUT_WIDTH;
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase5Circuit,
        test_mul_case5,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "big square test",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let out_base = BigUint::from(1usize) << Self::OUT_WIDTH;
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
                    let ab = bigint_chip.mul(ctx, &a_assigned, &a_assigned)?;
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase6Circuit,
        test_mul_case6,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "(1+x)(1+x+x^2) =  1 + 2x + 2x^2 + x^3",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let out_base = BigUint::from(1usize) << Self::OUT_WIDTH;
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulCase7Circuit,
        test_mul_case7,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            layouter.assign_region(
                || "(1+7x)(1+x+x^2) =  1 + 8x + 8x^2 + 7x^3",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let out_base = BigUint::from(1usize) << Self::OUT_WIDTH;
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModCase1Circuit,
        test_mulmod_case1,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "0 * (random) = 0 mod n",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let out_base = BigUint::from(1usize) << Self::OUT_WIDTH;
                    let zero_big = BigUint::from(0usize);
                    let a_big = zero_big.clone();
                    let a_assigned = bigint_chip.assign_constant_fresh(ctx, a_big)?;
                    let b_limbs = decompose_big::<F>(self.b.clone(), num_limbs, Self::OUT_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::OUT_WIDTH);
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModCase2Circuit,
        test_mulmod_case2,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "n * 1 mod n = 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::OUT_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_big = BigUint::from(1usize);
                    let b_assigned = bigint_chip.assign_constant_fresh(ctx, b_big)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::OUT_WIDTH);
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModCase3Circuit,
        test_mulmod_case3,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "(n - 1) * (n - 1) mod n = 1",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let n_sub_1 = &self.n - &1u8;
                    let a_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::OUT_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let b_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::OUT_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::OUT_WIDTH);
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );

    impl_bigint_test_circuit!(
        TestMulModCase4Circuit,
        test_mulmod_case4,
        64,
        2048,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "(n - 1) * (n - 2) mod n = 2",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let n_sub_1 = &self.n - &1u8;
                    let a_limbs = decompose_big::<F>(n_sub_1.clone(), num_limbs, Self::OUT_WIDTH);
                    let a_unassigned = UnassignedInteger::from(a_limbs);
                    let a_assigned = bigint_chip.assign_integer(ctx, a_unassigned)?;
                    let n_sub_2 = &self.n - &2u8;
                    let b_limbs = decompose_big::<F>(n_sub_2.clone(), num_limbs, Self::OUT_WIDTH);
                    let b_unassigned = UnassignedInteger::from(b_limbs);
                    let b_assigned = bigint_chip.assign_integer(ctx, b_unassigned)?;
                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, Self::OUT_WIDTH);
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
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    );
}
