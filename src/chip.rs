use crate::big_uint::BigUintInstructions;
use crate::{
    AssignedBigUint, AssignedRSAPubE, AssignedRSAPublicKey, AssignedRSASignature, BigUintConfig,
    Fresh, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature,
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

use num_bigint::BigUint;
use std::marker::PhantomData;

/// Configuration for [`RSAConfig`].
#[derive(Clone, Debug)]
pub struct RSAConfig<F: PrimeField> {
    /// Configuration for [`BigUintConfig`].
    biguint_config: BigUintConfig<F>,
    /// The default bit length of [`Fresh`] type integers in this chip.
    default_bits: usize,
    /// The bit length of exponents.
    exp_bits: usize,
}

impl<F: PrimeField> RSAInstructions<F> for RSAConfig<F> {
    /// Assigns a [`AssignedRSAPublicKey`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - a RSA public key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedRSAPublicKey`].
    fn assign_public_key<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        public_key: RSAPublicKey<F>,
    ) -> Result<AssignedRSAPublicKey<'v, F>, Error> {
        let biguint_config = self.biguint_config();
        let n = biguint_config.assign_integer(ctx, public_key.n, self.default_bits)?;
        let e = match public_key.e {
            RSAPubE::Var(e) => {
                let assigned = self.gate().load_witness(ctx, e.map(|v| biguint_to_fe(&v)));
                self.range().range_check(ctx, &assigned, self.exp_bits);
                AssignedRSAPubE::Var(assigned)
            }
            RSAPubE::Fix(e) => AssignedRSAPubE::Fix(e),
        };
        Ok(AssignedRSAPublicKey::new(n, e))
    }

    /// Assigns a [`AssignedRSASignature`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `signature` - a RSA signature to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedRSASignature`].
    fn assign_signature<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<'v, F>, Error> {
        let biguint_config = self.biguint_config();
        let c = biguint_config.assign_integer(ctx, signature.c, self.default_bits)?;
        Ok(AssignedRSASignature::new(c))
    }

    /// Given a base `x`, a RSA public key (e,n), performs the modular power `x^e mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `x` - a base integer.
    /// * `public_key` - an assigned RSA public key.
    ///
    /// # Return values
    /// Returns the modular power result `x^e mod n` as [`AssignedInteger<F, Fresh>`].
    fn modpow_public_key<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        x: &AssignedBigUint<'v, F, Fresh>,
        public_key: &AssignedRSAPublicKey<'v, F>,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error> {
        let biguint_config = self.biguint_config();
        biguint_config.assert_in_field(ctx, x, &public_key.n)?;
        let powed = match &public_key.e {
            AssignedRSAPubE::Var(e) => {
                biguint_config.pow_mod(ctx, x, e, &public_key.n, self.exp_bits)
            }
            AssignedRSAPubE::Fix(e) => biguint_config.pow_mod_fixed_exp(ctx, x, e, &public_key.n),
        }?;
        Ok(powed)
    }

    /// Given a RSA public key, a message hashed with SHA256, and a pkcs1v15 signature, verifies the signature with the public key and the hashed messaged.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - an assigned RSA public key.
    /// * `hashed_msg` - an assigned integer of the message hashed with SHA256.
    /// * `signature` - an assigned pkcs1v15 signature.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `signature` is valid for `public_key` and `hashed_msg`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn verify_pkcs1v15_signature<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        public_key: &AssignedRSAPublicKey<'v, F>,
        hashed_msg: &[AssignedValue<'v, F>],
        signature: &AssignedRSASignature<'v, F>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        let gate = self.gate();
        let mut is_eq = gate.load_constant(ctx, F::one());
        let powed = self.modpow_public_key(ctx, &signature.c, public_key)?;
        let hash_len = hashed_msg.len();
        assert_eq!(hash_len, 4);
        // 1. Check hashed data
        // 64 * 4 = 256 bit, that is the first 4 numbers.
        for (limb, hash) in powed.limbs()[0..hash_len].iter().zip(hashed_msg.iter()) {
            let is_hash_eq = gate.is_equal(
                ctx,
                QuantumCell::Existing(limb),
                QuantumCell::Existing(hash),
            );
            is_eq = gate.and(
                ctx,
                QuantumCell::Existing(&is_eq),
                QuantumCell::Existing(&is_hash_eq),
            );
        }

        // 2. Check hash prefix and 1 byte 0x00
        // sha256/152 bit
        // 0b00110000001100010011000000001101000001100000100101100000100001100100100000000001011001010000001100000100000000100000000100000101000000000000010000100000
        let is_prefix_64_1_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&powed.limbs()[hash_len]),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(217300885422736416u64))),
        );
        let is_prefix_64_2_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&powed.limbs()[hash_len + 1]),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(938447882527703397u64))),
        );
        let is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_prefix_64_1_eq),
        );
        let is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_prefix_64_2_eq),
        );
        // remain 24 bit
        let u32_v: BigUint = BigUint::from(1usize) << 32;
        let (remain_low, remain_high) = powed
            .limb(hash_len + 2)
            .value()
            .map(|v| {
                let big_v = fe_to_biguint(v);
                let low = biguint_to_fe::<F>(&(&big_v % &u32_v));
                let high = biguint_to_fe::<F>(&(&big_v / &u32_v));
                (low, high)
            })
            .unzip();
        let range = self.range();
        let remain_low = gate.load_witness(ctx, remain_low);
        range.range_check(ctx, &remain_low, 32);
        let remain_high = gate.load_witness(ctx, remain_high);
        range.range_check(ctx, &remain_high, 32);
        let remain_concat = gate.mul_add(
            ctx,
            QuantumCell::Existing(&remain_high),
            QuantumCell::Constant(biguint_to_fe(&u32_v)),
            QuantumCell::Existing(&remain_low),
        );
        gate.assert_equal(
            ctx,
            QuantumCell::Existing(&powed.limbs()[hash_len + 2]),
            QuantumCell::Existing(&remain_concat),
        );
        let is_prefix_32_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&remain_low),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(3158320u32))),
        );
        let is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_prefix_32_eq),
        );

        // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
        let is_ff_32_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&remain_high),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(4294967295u32))),
        );
        let mut is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_ff_32_eq),
        );
        let num_limbs = self.default_bits / self.biguint_config().limb_bits();
        for limb in powed.limbs()[(hash_len + 3)..(num_limbs - 1)].iter() {
            let is_ff_64_eq = gate.is_equal(
                ctx,
                QuantumCell::Existing(limb),
                QuantumCell::Constant(biguint_to_fe(&BigUint::from(18446744073709551615u64))),
            );
            is_eq = gate.and(
                ctx,
                QuantumCell::Existing(&is_eq),
                QuantumCell::Existing(&is_ff_64_eq),
            );
        }
        //562949953421311 = 0b1111111111111111111111111111111111111111111111111 = 0x00 || 0x01 || (0xff)^*
        let is_last_em_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&powed.limbs()[num_limbs - 1]),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(562949953421311u64))),
        );
        let is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_last_em_eq),
        );
        Ok(is_eq.clone())
    }
}

impl<F: PrimeField> RSAConfig<F> {
    /// Creates new [`RSAConfig`] from [`BigUintInstructions`].
    ///
    /// # Arguments
    /// * biguint_config - a configuration for [`BigUintConfig`].
    /// * default_bits - the default bit length of [`Fresh`] type integers in this chip.
    /// * exp_bits - the bit length of exponents.
    ///
    /// # Return values
    /// Returns new [`RSAConfig`].
    pub fn construct(
        biguint_config: BigUintConfig<F>,
        default_bits: usize,
        exp_bits: usize,
    ) -> Self {
        Self {
            biguint_config,
            default_bits,
            exp_bits,
        }
    }

    pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
        self.biguint_config.new_context(region)
    }

    /// Getter for [`BigUintConfig`].
    pub fn biguint_config(&self) -> &BigUintConfig<F> {
        &self.biguint_config
    }

    /// Getter for [`FlexGateConfig`].
    fn gate(&self) -> &FlexGateConfig<F> {
        &self.biguint_config.gate()
    }

    /// Getter for [`RangeConfig`].
    fn range(&self) -> &RangeConfig<F> {
        &self.biguint_config.range()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::big_uint::decompose_biguint;
    use halo2_base::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};

    use num_bigint::RandomBits;
    use num_traits::FromPrimitive;
    use rand::{thread_rng, Rng};

    macro_rules! impl_rsa_modpow_test_circuit {
        ($circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $limb_bits:expr, $k:expr, $should_be_error:expr, $( $synth:tt )*) => {
            struct $circuit_name<F: PrimeField> {
                n: BigUint,
                e: BigUint,
                x: BigUint,
                _f: PhantomData<F>
            }

            impl<F: PrimeField> $circuit_name<F> {
                const BITS_LEN:usize = $bits_len;
                const LIMB_BITS:usize = $limb_bits;
                const EXP_LIMB_BITS:usize = 5;
                const DEFAULT_E: u128 = 65537;
                const NUM_ADVICE:usize = 50;
                const NUM_FIXED:usize = 1;
                const NUM_LOOKUP_ADVICE:usize = 4;
                const LOOKUP_BITS:usize = 12;
            }

            impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
                type Config = RSAConfig<F>;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let range_config = RangeConfig::configure(meta,Vertical, &[Self::NUM_ADVICE], &[Self::NUM_LOOKUP_ADVICE], Self::NUM_FIXED, Self::LOOKUP_BITS, 0, $k);
                    let bigint_config = BigUintConfig::construct(range_config, Self::LIMB_BITS);
                    RSAConfig::construct(bigint_config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                fn run<F: PrimeField>() {
                    let mut rng = thread_rng();
                    let bits_len = $circuit_name::<F>::BITS_LEN as u64;
                    let mut n = BigUint::default();
                    while n.bits() != bits_len {
                        n = rng.sample(RandomBits::new(bits_len));
                    }
                    let e = rng.sample::<BigUint, _>(RandomBits::new($circuit_name::<F>::EXP_LIMB_BITS as u64)) % &n;
                    let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                    let circuit = $circuit_name::<F> {
                        n,
                        e,
                        x,
                        _f: PhantomData
                    };

                    let public_inputs = vec![];
                    let k = $k;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }
                run::<Fr>();
            }
        };
    }

    use crate::big_pow_mod;

    impl_rsa_modpow_test_circuit!(
        TestRSAModPow2048Circuit,
        test_rsa_modpow_2048_circuit,
        2048,
        64,
        14,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let biguint_config = config.biguint_config();
            let limb_bits = Self::LIMB_BITS;
            let num_limbs = Self::BITS_LEN / Self::LIMB_BITS;

            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let e_var = RSAPubE::Var(Value::known(self.e.clone()));
                    let e_fix = RSAPubE::Fix(BigUint::from_u128(Self::DEFAULT_E).unwrap());
                    let public_key_var = RSAPublicKey::new(Value::known(self.n.clone()), e_var);
                    let public_key_var = config.assign_public_key(ctx, public_key_var)?;
                    let public_key_fix = RSAPublicKey::new(Value::known(self.n.clone()), e_fix);
                    let public_key_fix = config.assign_public_key(ctx, public_key_fix)?;
                    let x_assigned = biguint_config.assign_integer(
                        ctx,
                        Value::known(self.x.clone()),
                        Self::BITS_LEN,
                    )?;
                    let powed_var = config.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                    let powed_fix = config.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;
                    let valid_powed_var = big_pow_mod(&self.x, &self.e, &self.n);
                    let valid_powed_fix =
                        big_pow_mod(&self.x, &BigUint::from(Self::DEFAULT_E), &self.n);
                    let valid_powed_var = biguint_config.assign_constant(ctx, valid_powed_var)?;
                    let valid_powed_fix = biguint_config.assign_constant(ctx, valid_powed_fix)?;
                    biguint_config.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;
                    biguint_config.assert_equal_fresh(ctx, &powed_fix, &valid_powed_fix)?;
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

    impl_rsa_modpow_test_circuit!(
        TestBadRSAModPow2048Circuit,
        test_bad_rsa_modpow_2048_circuit,
        2048,
        64,
        14,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let biguint_config = config.biguint_config();
            let limb_bits = Self::LIMB_BITS;
            let num_limbs = Self::BITS_LEN / Self::LIMB_BITS;

            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let e_var = RSAPubE::Var(Value::known(self.e.clone()));
                    let e_fix = RSAPubE::Fix(BigUint::from_u128(Self::DEFAULT_E).unwrap());
                    let public_key_var = RSAPublicKey::new(Value::known(self.n.clone()), e_var);
                    let public_key_var = config.assign_public_key(ctx, public_key_var)?;
                    let public_key_fix = RSAPublicKey::new(Value::known(self.n.clone()), e_fix);
                    let public_key_fix = config.assign_public_key(ctx, public_key_fix)?;
                    let x_assigned = biguint_config.assign_integer(
                        ctx,
                        Value::known(self.x.clone()),
                        Self::BITS_LEN,
                    )?;
                    let powed_var = config.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                    let powed_fix = config.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;
                    let max = biguint_config.max_value(ctx, powed_var.num_limbs())?;
                    biguint_config.assert_equal_fresh(ctx, &powed_var, &max)?;
                    let max = biguint_config.max_value(ctx, powed_fix.num_limbs())?;
                    biguint_config.assert_equal_fresh(ctx, &powed_fix, &max)?;
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

    impl_rsa_modpow_test_circuit!(
        TestRSAModPow1024Circuit,
        test_rsa_modpow_1024_circuit,
        1024,
        64,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let biguint_config = config.biguint_config();
            let limb_bits = Self::LIMB_BITS;
            let num_limbs = Self::BITS_LEN / Self::LIMB_BITS;

            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let e_var = RSAPubE::Var(Value::known(self.e.clone()));
                    let e_fix = RSAPubE::Fix(BigUint::from_u128(Self::DEFAULT_E).unwrap());
                    let public_key_var = RSAPublicKey::new(Value::known(self.n.clone()), e_var);
                    let public_key_var = config.assign_public_key(ctx, public_key_var)?;
                    let public_key_fix = RSAPublicKey::new(Value::known(self.n.clone()), e_fix);
                    let public_key_fix = config.assign_public_key(ctx, public_key_fix)?;
                    let x_assigned = biguint_config.assign_integer(
                        ctx,
                        Value::known(self.x.clone()),
                        Self::BITS_LEN,
                    )?;
                    let powed_var = config.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                    let powed_fix = config.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;
                    let valid_powed_var = big_pow_mod(&self.x, &self.e, &self.n);
                    let valid_powed_fix =
                        big_pow_mod(&self.x, &BigUint::from(Self::DEFAULT_E), &self.n);
                    let valid_powed_var = biguint_config.assign_constant(ctx, valid_powed_var)?;
                    let valid_powed_fix = biguint_config.assign_constant(ctx, valid_powed_fix)?;
                    biguint_config.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;
                    biguint_config.assert_equal_fresh(ctx, &powed_fix, &valid_powed_fix)?;
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

    impl_rsa_modpow_test_circuit!(
        TestBadRSAModPow1024Circuit,
        test_bad_rsa_modpow_1024_circuit,
        1024,
        64,
        13,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let biguint_config = config.biguint_config();
            let limb_bits = Self::LIMB_BITS;
            let num_limbs = Self::BITS_LEN / Self::LIMB_BITS;

            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let e_var = RSAPubE::Var(Value::known(self.e.clone()));
                    let e_fix = RSAPubE::Fix(BigUint::from_u128(Self::DEFAULT_E).unwrap());
                    let public_key_var = RSAPublicKey::new(Value::known(self.n.clone()), e_var);
                    let public_key_var = config.assign_public_key(ctx, public_key_var)?;
                    let public_key_fix = RSAPublicKey::new(Value::known(self.n.clone()), e_fix);
                    let public_key_fix = config.assign_public_key(ctx, public_key_fix)?;
                    let x_assigned = biguint_config.assign_integer(
                        ctx,
                        Value::known(self.x.clone()),
                        Self::BITS_LEN,
                    )?;
                    let powed_var = config.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                    let powed_fix = config.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;
                    let max = biguint_config.max_value(ctx, powed_var.num_limbs())?;
                    biguint_config.assert_equal_fresh(ctx, &powed_var, &max)?;
                    let max = biguint_config.max_value(ctx, powed_fix.num_limbs())?;
                    biguint_config.assert_equal_fresh(ctx, &powed_fix, &max)?;
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

    macro_rules! impl_rsa_signature_test_circuit {
        ($circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $limb_bits:expr, $k:expr, $should_be_error:expr, $( $synth:tt )*) => {
            struct $circuit_name<F: PrimeField> {
                _f: PhantomData<F>
            }

            impl<F: PrimeField> $circuit_name<F> {
                const BITS_LEN:usize = $bits_len;
                const LIMB_BITS:usize = $limb_bits;
                const EXP_LIMB_BITS:usize = 5;
                const DEFAULT_E: u128 = 65537;
                const NUM_ADVICE:usize = 50;
                const NUM_FIXED:usize = 1;
                const NUM_LOOKUP_ADVICE:usize = 4;
                const LOOKUP_BITS:usize = 12;
            }

            impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
                type Config = RSAConfig<F>;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let range_config = RangeConfig::configure(meta,Vertical, &[Self::NUM_ADVICE], &[Self::NUM_LOOKUP_ADVICE], Self::NUM_FIXED, Self::LOOKUP_BITS, 0, $k);
                    let bigint_config = BigUintConfig::construct(range_config, Self::LIMB_BITS);
                    RSAConfig::construct(bigint_config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                fn run<F: PrimeField>() {
                    let circuit = $circuit_name::<F> {
                        _f: PhantomData
                    };

                    let public_inputs = vec![];
                    let k = $k;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }
                run::<Fr>();
            }
        };
    }

    impl_rsa_signature_test_circuit!(
        TestRSASignatureCircuit1,
        test_rsa_signature_circuit1,
        2048,
        64,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let biguint_config = config.biguint_config();
            let limb_bits = Self::LIMB_BITS;
            let num_limbs = Self::BITS_LEN / Self::LIMB_BITS;

            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_big = BigUint::from_str("27333278531038650284292446400685983964543820405055158402397263907659995327446166369388984969315774410223081038389734916442552953312548988147687296936649645550823280957757266695625382122565413076484125874545818286099364801140117875853249691189224238587206753225612046406534868213180954324992542640955526040556053150097561640564120642863954208763490114707326811013163227280580130702236406906684353048490731840275232065153721031968704703853746667518350717957685569289022049487955447803273805415754478723962939325870164033644600353029240991739641247820015852898600430315191986948597672794286676575642204004244219381500407").unwrap();
                    let public_key = RSAPublicKey::new(Value::known(n_big), e_fix);
                    let public_key = config.assign_public_key(ctx, public_key)?;
                    let sign_big = BigUint::from_str("27166015521685750287064830171899789431519297967327068200526003963687696216659347317736779094212876326032375924944649760206771585778103092909024744594654706678288864890801000499430246054971129440518072676833029702477408973737931913964693831642228421821166326489172152903376352031367604507095742732994611253344812562891520292463788291973539285729019102238815435155266782647328690908245946607690372534644849495733662205697837732960032720813567898672483741410294744324300408404611458008868294953357660121510817012895745326996024006347446775298357303082471522757091056219893320485806442481065207020262668955919408138704593").unwrap();
                    let sign = RSASignature::new(Value::known(sign_big));
                    let sign = config.assign_signature(ctx, sign)?;
                    let hashed_msg_big = BigUint::from_str("83814198383102558219731078260892729932246618004265700685467928187377105751529").unwrap();
                    let hashed_msg_limbs = decompose_biguint::<F>(&hashed_msg_big, 4, 256/4);
                    let hashed_msg_assigned = hashed_msg_limbs.into_iter().map(|limb| config.gate().load_witness(ctx, Value::known(limb))).collect::<Vec<AssignedValue<F>>>();
                    let is_valid = config.verify_pkcs1v15_signature(ctx, &public_key, &hashed_msg_assigned, &sign)?;
                    config.gate().assert_is_const(ctx, &is_valid, F::one());
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

    impl_rsa_signature_test_circuit!(
        TestRSASignatureCircuit2,
        test_rsa_signature_circuit2,
        2048,
        64,
        13,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let biguint_config = config.biguint_config();
            let limb_bits = Self::LIMB_BITS;
            let num_limbs = Self::BITS_LEN / Self::LIMB_BITS;

            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "random rsa modpow test with 2048 bits public keys",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_big = BigUint::from_str("24226501697440012621102249466312043787685293040734225606346036389705515508545746221669035424138747582133889500686654172873671086178893587422987328751464627501601101326475761646014534358699943642495332701081302954020983110372109611581202820849485662540890985814355975252780310958088652613376767040069489530039075302709233494829280591680666351811024913107949144932224439129715181798714328219977771472462901856297952813239115577652450722815852332547886777292613005505949100406231716599634852632308325816916535875123863510650526931916871614411907700873376659841257216885666098127478325534982891697988739616416855214839339").unwrap();
                    let public_key = RSAPublicKey::new(Value::known(n_big), e_fix);
                    let public_key = config.assign_public_key(ctx, public_key)?;
                    let sign_big = BigUint::from_str("18928545496959757512579438348223103860103247450097569223971486743312798156950374943336714741350742176674694049986481729075548718599712271054643150030165230392897481507710187505775911256946250999396358633095137650326818007610162375520522758780751710735664264200260854016867498935206556916247099180950775474524799944404833222133011134000549939512938205188018503377612813102061504146765520561811620128786062447005833886367575841545493555268747671930923697279690399480501746857825917608323993022396398648205737336204493624060285359455268389160802763426461171262704764369336704988874821898000892148693988241020931055723252").unwrap();
                    let sign = RSASignature::new(Value::known(sign_big));
                    let sign = config.assign_signature(ctx, sign)?;
                    let hashed_msg_big = BigUint::from_str("83814198383102558219731078260892729932246618004265700685467928187377105751529").unwrap();
                    let hashed_msg_limbs = decompose_biguint::<F>(&hashed_msg_big, 4, 256/4);
                    let hashed_msg_assigned = hashed_msg_limbs.into_iter().map(|limb| config.gate().load_witness(ctx, Value::known(limb))).collect::<Vec<AssignedValue<F>>>();
                    let is_valid = config.verify_pkcs1v15_signature(ctx, &public_key, &hashed_msg_assigned, &sign)?;
                    config.gate().assert_is_const(ctx, &is_valid, F::one());
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

    impl_rsa_signature_test_circuit!(
        TestBadRSASignatureCircuit,
        test_bad_rsa_signature_circuit,
        2048,
        64,
        13,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let biguint_config = config.biguint_config();
            let limb_bits = Self::LIMB_BITS;
            let num_limbs = Self::BITS_LEN / Self::LIMB_BITS;

            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "rsa signature test using 2048 bits public keys with a uncorrect case",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_big = BigUint::from_str("24226501697440012621102249466312043787685293040734225606346036389705515508545746221669035424138747582133889500686654172873671086178893587422987328751464627501601101326475761646014534358699943642495332701081302954020983110372109611581202820849485662540890985814355975252780310958088652613376767040069489530039075302709233494829280591680666351811024913107949144932224439129715181798714328219977771472462901856297952813239115577652450722815852332547886777292613005505949100406231716599634852632308325816916535875123863510650526931916871614411907700873376659841257216885666098127478325534982891697988739616416855214839339").unwrap();
                    let public_key = RSAPublicKey::new(Value::known(n_big), e_fix);
                    let public_key = config.assign_public_key(ctx, public_key)?;
                    let sign_big = BigUint::from_str("18928545496959756512579438348223103860103247450097569223971486743312798156950374943336714741350742176674694049986481729075548718599712271054643150030165230392897481507710187505775911256946250999396358633095137650326818007610162375520522758780751710735664264200260854016867498935206556916247099180950775474524799944404833222133011134000549939512938205188018503377612813102061504146765520561811620128786062447005833886367575841545493555268747671930923697279690399480501746857825917608323993022396398648205737336204493624060285359455268389160802763426461171262704764369336704988874821898000892148693988241020931055723252").unwrap();
                    let sign = RSASignature::new(Value::known(sign_big));
                    let sign = config.assign_signature(ctx, sign)?;
                    let hashed_msg_big = BigUint::from_str("83814198383102558219731078260892729932246618004265700685467928187377105751529").unwrap();
                    let hashed_msg_limbs = decompose_biguint::<F>(&hashed_msg_big, 4, 256/4);
                    let hashed_msg_assigned = hashed_msg_limbs.into_iter().map(|limb| config.gate().load_witness(ctx, Value::known(limb))).collect::<Vec<AssignedValue<F>>>();
                    let is_valid = config.verify_pkcs1v15_signature(ctx, &public_key, &hashed_msg_assigned, &sign)?;
                    config.gate().assert_is_const(ctx, &is_valid, F::one());
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

    impl_rsa_signature_test_circuit!(
        TestBadRSASignatureCircuit2,
        test_bad_rsa_signature_circuit2,
        2048,
        64,
        13,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let biguint_config = config.biguint_config();
            let limb_bits = Self::LIMB_BITS;
            let num_limbs = Self::BITS_LEN / Self::LIMB_BITS;

            config.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "rsa signature test using 2048 bits public keys with a uncorrect case",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let n_big = BigUint::from_str("24226501697440012621102249466312043787685293040734225606346036389705515508545746221669035424138747582133889500686654172873671086178893587422987328751464627501601101326475761646014534358699943642495332701081302954020983110372109611581202820849485662540890985814355975252780310958088652613376767040069489530039075302709233494829280591680666351811024913107949144932224439129715181798714328219977771472462901856297952813239115577652450722815852332547886777292613005505949100406231716599634852632308325816916535875123863510650526931916871614411907700873376659841257216885666098127478325534982891697988739616416855214839339").unwrap();
                    let public_key = RSAPublicKey::new(Value::known(n_big), e_fix);
                    let public_key = config.assign_public_key(ctx, public_key)?;
                    let sign_big = BigUint::from_str("18928545496959756512579438348223103860103247450097569223971486743312798156950374943336714741350742176674694049986481729075548718599712271054643150030165230392897481507710187505775911256946250999396358633095137650326818007610162375520522758780751710735664264200260854016867498935206556916247099180950775474524799944404833222133011134000549939512938205188018503377612813102061504146765520561811620128786062447005833886367575841545493555268747671930923697279690399480501746857825917608323993022396398648205737336204493624060285359455268389160802763426461171262704764369336704988874821898000892148693988241020931055723252").unwrap();
                    let sign = RSASignature::new(Value::known(sign_big));
                    let sign = config.assign_signature(ctx, sign)?;
                    let hashed_msg_big = BigUint::from_str("83814198383102558219731078260892729932246618004265700685467928187377105751529").unwrap();
                    let hashed_msg_limbs = decompose_biguint::<F>(&hashed_msg_big, 4, 256/4);
                    let hashed_msg_assigned = hashed_msg_limbs.into_iter().map(|limb| config.gate().load_witness(ctx, Value::known(limb))).collect::<Vec<AssignedValue<F>>>();
                    let is_valid = config.verify_pkcs1v15_signature(ctx, &public_key, &hashed_msg_assigned, &sign)?;
                    config.gate().assert_is_const(ctx, &is_valid, F::one());
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
}
