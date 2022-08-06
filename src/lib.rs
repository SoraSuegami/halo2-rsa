mod pow_integer;
mod rsa_signature;
pub use pow_integer::*;
pub use rsa_signature::*;

use halo2_proofs::arithmetic::FieldExt;
use integer::{rns::Integer, AssignedInteger};

#[derive(Clone, Debug)]
pub struct RSAPublicKey<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub n: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub e: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub n: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub e: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}
