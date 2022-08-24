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

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        integer: BigUint,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {
        let out_width = self.out_width;
        let int_bits_size = Self::bits_size(&integer);
        let num_limbs = self.num_limbs;
        assert_eq!(int_bits_size / out_width, num_limbs);
        let limbs = decompose_big::<F>(integer, num_limbs, int_bits_size);
        let main_gate = self.main_gate();
        let mut assigned_limbs: Vec<AssignedLimb<F, Fresh>> = Vec::with_capacity(num_limbs);

        for limb in limbs.iter() {
            let assigned = main_gate.assign_constant(ctx, *limb)?;
            assigned_limbs.push(AssignedLimb::from(assigned));
        }
        Ok(AssignedInteger::new(&assigned_limbs))
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

    fn modular_mul(
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
        let n = n1 + n2;
        let mut eq_a_limbs: Vec<AssignedLimb<F, Muled>> = Vec::with_capacity(n - 1);
        let mut eq_b_limbs: Vec<AssignedLimb<F, Muled>> = Vec::with_capacity(n - 1);
        let main_gate = self.main_gate();
        for i in 0..(n - 1) {
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

    fn compute_range_lens(out_width: usize, num_limbs: usize) -> (Vec<usize>, Vec<usize>) {
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
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2wrong::halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };

    #[derive(Clone, Debug)]
    struct TestBigIntCircuit<F: FieldExt> {
        a: BigUint,
        b: BigUint,
        n: BigUint,
        _f: PhantomData<F>,
    }

    impl<F: FieldExt> TestBigIntCircuit<F> {
        const OUT_WIDTH: usize = 64;
        const BITS_LEN: usize = 2048;
        fn bigint_chip(&self, config: BigIntConfig) -> BigIntChip<F> {
            BigIntChip::new(config, Self::OUT_WIDTH, Self::BITS_LEN)
        }
    }

    impl<F: FieldExt> Circuit<F> for TestBigIntCircuit<F> {
        type Config = BigIntConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let main_gate_config = MainGate::<F>::configure(meta);
            let (composition_bit_lens, overflow_bit_lens) = BigIntChip::<F>::compute_range_lens(
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

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let bigint_chip = self.bigint_chip(config);
            let num_limbs = Self::BITS_LEN / Self::OUT_WIDTH;
            layouter.assign_region(
                || "assign aux values",
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
                    let ab = bigint_chip.mul(ctx, &a_assigned, &b_assigned)?;
                    let ba = bigint_chip.mul(ctx, &b_assigned, &a_assigned)?;
                    bigint_chip.assert_equal_muled(
                        ctx,
                        &ab,
                        &ba,
                        a_assigned.num_limbs(),
                        b_assigned.num_limbs(),
                    )?;
                    let ab_mod_n =
                        bigint_chip.modular_mul(ctx, &a_assigned, &b_assigned, &n_assigned)?;
                    let ba_mod_n =
                        bigint_chip.modular_mul(ctx, &b_assigned, &a_assigned, &n_assigned)?;
                    bigint_chip.assert_equal_fresh(ctx, &ab_mod_n, &ba_mod_n)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;
            Ok(())
        }
    }

    #[test]
    fn test_bigint_chip() {
        use halo2wrong::halo2::dev::MockProver;
        use num_bigint::RandomBits;
        use rand::{thread_rng, Rng};
        fn run<F: FieldExt>() {
            let mut rng = thread_rng();
            let bits_len = TestBigIntCircuit::<F>::BITS_LEN as u64;
            let mut n = BigUint::default();
            while n.bits() != bits_len {
                n = rng.sample(RandomBits::new(bits_len));
            }
            let a = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
            let b = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
            println!("ab {}", (&a * &b).to_str_radix(16));
            println!(
                "size a {} b {} n {} ab {} q {}",
                a.bits(),
                b.bits(),
                n.bits(),
                (&a * &b).bits(),
                (&a * &b / &n).bits(),
            );
            let circuit = TestBigIntCircuit::<F> {
                a,
                b,
                n,
                _f: PhantomData,
            };

            let public_inputs = vec![vec![]];
            let k = 14;
            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            assert_eq!(prover.verify(), Ok(()));
        }

        use halo2wrong::curves::bn256::Fq as BnFq;
        use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
        use halo2wrong::curves::secp256k1::Secp256k1Affine as Secp256k1;
        for _ in 0..10 {
            run::<BnFq>();
            run::<PastaFp>();
            run::<PastaFq>();
        }
    }
}
