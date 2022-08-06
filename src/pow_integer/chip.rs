use super::PowIntegerInstructions;
use halo2_proofs::arithmetic::Field;
use integer::instructions::{IntegerInstructions, Range};
use integer::rns::{Common, Integer, Rns};
use integer::{AssignedInteger, IntegerChip, IntegerConfig, UnassignedInteger};
use maingate::halo2::arithmetic::FieldExt;
use maingate::halo2::plonk::Error;
use maingate::{halo2, AssignedCondition, MainGateInstructions, RegionCtx};
use maingate::{MainGate, MainGateConfig};
use maingate::{RangeChip, RangeConfig};
use std::rc::Rc;

/// Configuration for [`PowIntegerChip`]
#[derive(Clone, Debug)]
pub struct PowIntegerConfig {
    /// Configuration for [`IntegerChip`]
    int_config: IntegerConfig,
}

impl PowIntegerConfig {
    // Creates a new [`PowIntegerConfig`] from a [`RangeConfig`] and a
    /// [`MainGateConfig`]
    pub fn new(range_config: RangeConfig, main_gate_config: MainGateConfig) -> Self {
        let int_config = IntegerConfig::new(range_config, main_gate_config);
        Self { int_config }
    }

    pub fn int_config(&self) -> IntegerConfig {
        self.int_config.clone()
    }
}

/// Chip for pow_integer instructions
#[derive(Debug)]
pub struct PowIntegerChip<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    /// Chip configuration
    config: PowIntegerConfig,
    /// Residue number system used to represent the integers
    rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
}

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    PowIntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Residue numeral system
    pub fn rns() -> Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        Rns::construct()
    }

    pub fn new(config: PowIntegerConfig) -> Self {
        let rns = Rc::new(Self::rns());
        Self { config, rns }
    }

    pub fn int_chip(&self) -> IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        IntegerChip::new(self.config.int_config(), Rc::clone(&self.rns))
    }
}

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    PowIntegerInstructions<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    for PowIntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn pow_fixed(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        exp: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let exp_bytes = exp.value().to_bytes_le();
        //let one_biguint = big_uint::one();
        let int_chip = self.int_chip();
        let mut result = int_chip.assign_constant(ctx, W::one())?;
        let mut powed = a.clone();
        for byte in exp_bytes.iter() {
            for i in 0..8 {
                if ((*byte >> i) & 1) == 1 {
                    result = int_chip.mul(ctx, &result, &powed)?;
                }
                powed = int_chip.square(ctx, &powed)?;
            }
        }
        Ok(result)
    }
}

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerInstructions<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    for PowIntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Assigns an [`Integer`] to a cell in the circuit with range check for the
    /// appropriate [`Range`].
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        range: Range,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().assign_integer(ctx, integer, range)
    }

    /// Assigns an [`Integer`] constant to a cell in the circuit returning an
    /// [`AssignedInteger`].
    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: W,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().assign_constant(ctx, integer)
    }

    /// Decomposes an [`AssignedInteger`] into its bit representation.
    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedCondition<N>>, Error> {
        self.int_chip().decompose(ctx, integer)
    }

    /// Adds 2 [`AssignedInteger`].
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().add(ctx, a, b)
    }

    /// Adds up 3 [`AssignedInteger`]
    fn add_add(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_0: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_1: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().add_add(ctx, a, b_0, b_1)
    }

    /// Adds an [`AssignedInteger`] and a constant.
    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().add_constant(ctx, a, b)
    }

    /// Multiplies an [`AssignedInteger`] by 2.
    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().mul2(ctx, a)
    }

    /// Multiplies an [`AssignedInteger`] by 3.
    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().mul3(ctx, a)
    }

    /// Substracts an [`AssignedInteger`].
    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().sub(ctx, a, b)
    }

    /// Substracts 2 [`AssignedInteger`].
    fn sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_0: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_1: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().sub_sub(ctx, a, b_0, b_1)
    }

    /// Multiplies an [`AssignedInteger`] by -1.
    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().neg(ctx, a)
    }

    /// Multiplies 2 [`AssignedInteger`].
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().mul(ctx, a, b)
    }

    /// Multiplies [`AssignedInteger`] by constant.
    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().mul_constant(ctx, a, b)
    }

    /// Check 2 [`AssignedInteger`] are inverses, equivalently their product is
    /// 1.
    fn mul_into_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().mul_into_one(ctx, a, b)
    }

    /// Squares an [`AssignedInteger`].
    fn square(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().square(ctx, a)
    }

    /// Divides 2 [`AssignedInteger`]. An [`AssignedCondition`] is returned
    /// along with the division result indicating if the operation was
    /// successful.
    fn div(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<
        (
            AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedCondition<N>,
        ),
        Error,
    > {
        self.int_chip().div(ctx, a, b)
    }

    /// Divides 2 [`AssignedInteger`]. Assumes denominator is not zero.
    fn div_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().div_incomplete(ctx, a, b)
    }

    /// Inverts an [`AssignedInteger`]. An [`AssignedCondition`] is returned
    /// along with the inversion result indicating if the operation was
    /// successful
    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<
        (
            AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedCondition<N>,
        ),
        Error,
    > {
        self.int_chip().invert(ctx, a)
    }

    /// Inverts an [`AssignedInteger`]. Assumes the input is not zero.
    fn invert_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().invert_incomplete(ctx, a)
    }

    /// Applies reduction to an [`AssignedInteger`]. Reduces the input less than
    /// next power of two of the modulus
    fn reduce(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().reduce(ctx, a)
    }

    /// Constraints that two [`AssignedInteger`] are equal.
    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_equal(ctx, a, b)
    }

    /// Constraints that limbs of two [`AssignedInteger`] are equal.
    fn assert_strict_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_strict_equal(ctx, a, b)
    }

    /// Constraints that two [`AssignedInteger`] are not equal.
    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_not_equal(ctx, a, b)
    }

    /// Constraints that an [`AssignedInteger`] is not equal to zero
    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_not_zero(ctx, a)
    }

    /// Constraints that an [`AssignedInteger`] is equal to zero
    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_zero(ctx, a)
    }

    /// Constraints that limbs of an [`AssignedInteger`] is equal to zero
    fn assert_strict_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_strict_zero(ctx, a)
    }

    /// Constraints that first limb of an [`AssignedInteger`] is equal to one
    /// and others are zero
    fn assert_strict_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_strict_one(ctx, a)
    }

    /// Constraints that first limb of an [`AssignedInteger`] is a bit
    /// and others are zero
    fn assert_strict_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_strict_bit(ctx, a)
    }

    /// Constraints that an [`AssignedInteger`] is less than modulus
    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        input: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        self.int_chip().assert_in_field(ctx, input)
    }

    /// Given an [`AssignedCondition`] returns picks one of two
    /// [`AssignedInteger`]
    fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().select(ctx, a, b, cond)
    }

    /// Given an [`AssignedCondition`] returns picks either an
    /// [`AssignedInteger`] or an unassigned integer
    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().select_or_assign(ctx, a, b, cond)
    }

    /// Tries to apply reduction to an [`AssignedInteger`] that is not in this
    /// wrong field
    fn reduce_external<T: FieldExt>(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<T, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.int_chip().reduce_external(ctx, a)
    }

    /// Applies % 2 to the given input
    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedCondition<N>, Error> {
        self.int_chip().sign(ctx, a)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use maingate::halo2::plonk::{Circuit, ConstraintSystem, Error};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        range_config: RangeConfig,
        main_gate_config: MainGateConfig,
    }

    impl TestCircuitConfig {
        fn new<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize>(
            meta: &mut ConstraintSystem<N>,
        ) -> Self {
            let main_gate_config = MainGate::<N>::configure(meta);

            let overflow_bit_lens = rns::<W, N, BIT_LEN_LIMB>().overflow_lengths();
            let composition_bit_len = BIT_LEN_LIMB / 4;
            let range_config = RangeChip::<N>::configure(
                meta,
                &main_gate_config,
                vec![composition_bit_len],
                overflow_bit_lens,
            );

            TestCircuitConfig {
                range_config,
                main_gate_config,
            }
        }

        fn pow_integer_config(&self) -> PowIntegerConfig {
            PowIntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
        }

        fn config_range<N: FieldExt>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
            let range_chip = RangeChip::<N>::new(self.range_config.clone());
            range_chip.load_composition_tables(layouter)?;
            range_chip.load_overflow_tables(layouter)?;

            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct TestPowCircuit<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize> {
        rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    }

    impl<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize> TestPowCircuit<W, N, BIT_LEN_LIMB> {
        fn pow_integer_chip(
            &self,
            config: TestCircuitConfig,
        ) -> PowIntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            let pow_int_config = config.pow_integer_config();
            PowIntegerChip::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(pow_int_config)
        }
    }

    impl<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize> Circuit<N>
        for TestPowCircuit<W, N, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N, BIT_LEN_LIMB>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let pow_int_chip = self.pow_integer_chip(config.clone());
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let three = Integer::from_fe(W::from_u128(3), Rc::clone(&self.rns));

                    let a = pow_int_chip.assign_constant(ctx, W::from_u128(2))?;
                    let powed = pow_int_chip.pow_fixed(ctx, &a, &three)?;

                    let b = pow_int_chip.assign_constant(ctx, W::from_u128(8))?;
                    pow_int_chip.assert_strict_equal(ctx, &powed, &b)?;
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    }

    use core::panic;
    use maingate::halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use maingate::halo2::dev::MockProver;
    use maingate::{
        big_to_fe, decompose_big, fe_to_big, halo2, AssignedCondition, MainGate, MainGateConfig,
        MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
    };

    const NUMBER_OF_LIMBS: usize = 4;

    fn rns<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize>(
    ) -> Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct()
    }

    fn setup<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize>(
    ) -> (Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, u32) {
        let rns = rns();
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        (rns, k)
    }

    use halo2wrong::curves::bn256::{Fq as BnBase, Fr as BnScalar};
    use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
    use halo2wrong::curves::secp256k1::{Fp as Secp256k1Base, Fq as Secp256k1Scalar};
    #[test]
    fn test_pow_int_circuit() {
        let (rns, k): (Rns<Secp256k1Base, BnScalar, NUMBER_OF_LIMBS, 68>, u32) = setup();

        let circuit = TestPowCircuit::<Secp256k1Base, BnScalar, 68> { rns: Rc::new(rns) };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
