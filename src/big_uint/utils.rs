use halo2_base::{
    halo2_proofs::circuit::Value,
    utils::{
        bigint_to_fe, biguint_to_fe, bit_length, decompose_bigint_option, decompose_biguint,
        fe_to_biguint, modulus, PrimeField,
    },
};
use num_bigint::{BigInt, BigUint};
use num_traits::One;

pub(crate) fn big_pow_mod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
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

pub(crate) struct CarryModParams<F: PrimeField> {
    pub limb_bits: usize,
    pub num_limbs: usize,

    pub num_limbs_bits: usize,
    pub num_limbs_log2_ceil: usize,
    pub limb_bases: Vec<F>,
    pub limb_base_big: BigInt,
    pub limb_mask: BigUint,

    pub p: BigInt,
    pub p_limbs: Vec<F>,
    pub p_native: F,
}

impl<F: PrimeField> CarryModParams<F> {
    pub fn new(limb_bits: usize, num_limbs: usize, p: BigUint) -> Self {
        // https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-ecc/src/fields/fp.rs#L96
        let limb_mask = (BigUint::from(1u64) << limb_bits) - 1usize;
        let p_limbs = decompose_biguint(&p, num_limbs, limb_bits);
        let native_modulus = modulus::<F>();
        let p_native = biguint_to_fe(&(&p % &native_modulus));

        let limb_base = biguint_to_fe::<F>(&(BigUint::one() << limb_bits));
        let mut limb_bases = Vec::with_capacity(num_limbs);
        limb_bases.push(F::one());
        while limb_bases.len() != num_limbs {
            limb_bases.push(limb_base * limb_bases.last().unwrap());
        }

        Self {
            limb_bits,
            num_limbs,
            num_limbs_bits: bit_length(num_limbs as u64),
            num_limbs_log2_ceil: bit_length(num_limbs as u64),
            limb_bases,
            limb_base_big: BigInt::one() << limb_bits,
            limb_mask,
            p: p.into(),
            p_limbs,
            p_native,
        }
    }
}
