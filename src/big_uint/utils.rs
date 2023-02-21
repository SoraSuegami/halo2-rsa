use halo2_base::{
    halo2_proofs::circuit::Value,
    utils::{
        bigint_to_fe, biguint_to_fe, bit_length, decompose_bigint as _decompose_bigint,
        decompose_biguint as _decompose_biguint, modulus, PrimeField,
    },
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed};

pub fn decompose_bigint<F: PrimeField>(
    e: &BigInt,
    number_of_limbs: usize,
    limb_bits_len: usize,
) -> Vec<F> {
    if e.is_negative() {
        decompose_biguint::<F>(e.magnitude(), number_of_limbs, limb_bits_len)
            .into_iter()
            .map(|x| -x)
            .collect()
    } else {
        decompose_biguint(e.magnitude(), number_of_limbs, limb_bits_len)
    }
}

pub fn decompose_biguint<F: PrimeField>(
    e: &BigUint,
    number_of_limbs: usize,
    limb_bits_len: usize,
) -> Vec<F> {
    assert!(limb_bits_len < 128);
    if limb_bits_len <= 64 {
        decompose_u64_digits_to_limbs(e.to_u64_digits(), number_of_limbs, limb_bits_len)
            .into_iter()
            .map(|v| F::from(v))
            .collect()
    } else {
        _decompose_biguint(e, number_of_limbs, limb_bits_len)
    }
}

// https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-base/src/utils.rs#L61
pub(crate) fn decompose_u64_digits_to_limbs(
    e: impl IntoIterator<Item = u64>,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<u64> {
    let mut e = e.into_iter();
    let mask: u64 = ((1u128 << bit_len) - 1u128) as u64;
    let mut u64_digit = e.next().unwrap_or(0);
    let mut rem = 64;
    (0..number_of_limbs)
        .map(|_| match rem.cmp(&bit_len) {
            core::cmp::Ordering::Greater => {
                let limb = u64_digit & mask;
                u64_digit >>= bit_len;
                rem -= bit_len;
                limb
            }
            core::cmp::Ordering::Equal => {
                let limb = u64_digit & mask;
                u64_digit = e.next().unwrap_or(0);
                rem = 64;
                limb
            }
            core::cmp::Ordering::Less => {
                let mut limb = u64_digit;
                u64_digit = e.next().unwrap_or(0);
                limb |= (u64_digit & ((1 << (bit_len - rem)) - 1)) << rem;
                u64_digit >>= bit_len - rem;
                rem += 64 - bit_len;
                limb
            }
        })
        .collect()
}

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

// pub(crate) struct CarryModParams<F: PrimeField> {
//     pub limb_bits: usize,
//     pub num_limbs: usize,

//     pub num_limbs_bits: usize,
//     pub num_limbs_log2_ceil: usize,
//     pub limb_bases: Vec<F>,
//     pub limb_base_big: BigInt,
//     pub limb_mask: BigUint,

//     pub p: BigInt,
//     pub p_limbs: Vec<F>,
//     pub p_native: F,
// }

// impl<F: PrimeField> CarryModParams<F> {
//     pub fn new(limb_bits: usize, num_limbs: usize, p: BigInt) -> Self {
//         // https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-ecc/src/fields/fp.rs#L96
//         let limb_mask = (BigUint::from(1u64) << limb_bits) - 1usize;
//         let p_limbs = decompose_bigint(&p, num_limbs, limb_bits);
//         let native_modulus = BigInt::from_biguint(Sign::Plus, modulus::<F>());
//         let p_native = bigint_to_fe(&(&p % &native_modulus));

//         let limb_base = biguint_to_fe::<F>(&(BigUint::one() << limb_bits));
//         let mut limb_bases = Vec::with_capacity(num_limbs);
//         limb_bases.push(F::one());
//         while limb_bases.len() != num_limbs {
//             limb_bases.push(limb_base * limb_bases.last().unwrap());
//         }

//         Self {
//             limb_bits,
//             num_limbs,
//             num_limbs_bits: bit_length(num_limbs as u64),
//             num_limbs_log2_ceil: bit_length(num_limbs as u64),
//             limb_bases,
//             limb_base_big: BigInt::one() << limb_bits,
//             limb_mask,
//             p: p.into(),
//             p_limbs,
//             p_native,
//         }
//     }
// }
