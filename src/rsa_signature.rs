use super::{AssignedRSAPublicKey, RSAPublicKey};
use halo2_proofs::arithmetic::FieldExt;
use integer::{rns::Integer, AssignedInteger};
#[derive(Clone, Debug)]
pub struct RSASignature<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>);

#[derive(Clone, Debug)]
pub struct AssignedRSASignature<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>);
