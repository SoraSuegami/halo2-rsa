pub mod big_integer;
//mod rsa_signature;
mod chip;
mod instructions;
use big_integer::*;
//use chip::*;
pub use chip::*;
use halo2wrong::halo2::arithmetic::FieldExt;
pub use instructions::*;
use num_bigint::BigUint;

#[derive(Clone, Debug)]
pub enum RSAPubE<F: FieldExt> {
    Var(UnassignedInteger<F>),
    Fix(BigUint),
}

#[derive(Clone, Debug)]
pub enum AssignedRSAPubE<F: FieldExt> {
    Var(AssignedInteger<F, Fresh>),
    Fix(BigUint),
}

#[derive(Clone, Debug)]
pub struct RSAPublicKey<F: FieldExt> {
    n: UnassignedInteger<F>,
    e: RSAPubE<F>,
}

impl<F: FieldExt> RSAPublicKey<F> {
    const FIXED_E: u128 = 65537;
    pub fn new(n: UnassignedInteger<F>, e: UnassignedInteger<F>) -> Self {
        let e = RSAPubE::Var(e);
        Self { n, e }
    }

    pub fn new_with_fixed_e(n: UnassignedInteger<F>, e: BigUint) -> Self {
        let e = RSAPubE::Fix(e);
        Self { n, e }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<F: FieldExt> {
    n: AssignedInteger<F, Fresh>,
    e: AssignedRSAPubE<F>,
}

impl<F: FieldExt> AssignedRSAPublicKey<F> {
    pub fn new(n: AssignedInteger<F, Fresh>, e: AssignedRSAPubE<F>) -> Self {
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
