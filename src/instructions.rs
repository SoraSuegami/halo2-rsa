use crate::{
    AssignedBigUint, AssignedRSAPublicKey, AssignedRSASignature, Fresh, RSAPublicKey, RSASignature,
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
/// Instructions for RSA operations.
pub trait RSAInstructions<F: PrimeField> {
    /// Assigns a [`AssignedRSAPublicKey`].
    fn assign_public_key<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        public_key: RSAPublicKey<F>,
    ) -> Result<AssignedRSAPublicKey<'v, F>, Error>;

    /// Assigns a [`AssignedRSASignature`].
    fn assign_signature<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<'v, F>, Error>;

    /// Given a base `x`, a RSA public key (e,n), performs the modular power `x^e mod n`.
    fn modpow_public_key<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        x: &AssignedBigUint<'v, F, Fresh>,
        public_key: &AssignedRSAPublicKey<'v, F>,
    ) -> Result<AssignedBigUint<'v, F, Fresh>, Error>;

    /// Given a RSA public key, a message hashed with SHA256, and a pkcs1v15 signature, verifies the signature with the public key and the hashed messaged.
    fn verify_pkcs1v15_signature<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        public_key: &AssignedRSAPublicKey<'v, F>,
        hashed_msg: &[AssignedValue<'v, F>],
        signature: &AssignedRSASignature<'v, F>,
    ) -> Result<AssignedValue<'v, F>, Error>;
}
