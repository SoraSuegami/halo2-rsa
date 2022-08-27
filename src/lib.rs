mod big_integer;
//mod rsa_signature;
mod chip;
pub use big_integer::*;
pub use chip::*;
//pub use rsa_signature::*;
use halo2wrong::halo2::arithmetic::FieldExt;

#[derive(Clone, Debug)]
pub struct RSAPublicKey<F: FieldExt> {
    n: UnassignedInteger<F>,
    e: UnassignedInteger<F>,
}

impl<F: FieldExt> RSAPublicKey<F> {
    const FIXED_E: u128 = 65537;
    pub fn new(n: UnassignedInteger<F>, e: UnassignedInteger<F>) -> Self {
        Self { n, e }
    }

    pub fn new_with_fixed_e(n: UnassignedInteger<F>) -> Self {
        Self {
            n,
            e: UnassignedInteger::from(vec![F::from_u128(Self::FIXED_E)]),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<F: FieldExt> {
    n: AssignedInteger<F, Fresh>,
    e: AssignedInteger<F, Fresh>,
}

impl<F: FieldExt> AssignedRSAPublicKey<F> {
    pub fn new(n: AssignedInteger<F, Fresh>, e: AssignedInteger<F, Fresh>) -> Self {
        Self { n, e }
    }
}

#[derive(Clone, Debug)]
pub struct RSASignature<F: FieldExt> {
    c: UnassignedInteger<F>,
}

impl<F: FieldExt> RSASignature<F> {
    pub fn new(c: UnassignedInteger<F>) -> Self {
        Self { c }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedRSASignature<F: FieldExt> {
    c: AssignedInteger<F, Fresh>,
}

impl<F: FieldExt> AssignedRSASignature<F> {
    pub fn new(c: AssignedInteger<F, Fresh>) -> Self {
        Self { c }
    }
}
