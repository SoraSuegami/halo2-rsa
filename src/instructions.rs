use crate::{
    AssignedInteger, AssignedRSAPublicKey, AssignedRSASignature, Fresh, RSAPublicKey, RSASignature,
};
use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use maingate::{AssignedValue, RegionCtx};

/// Instructions for RSA operations.
pub trait RSAInstructions<F: FieldExt> {
    /// Assigns a [`AssignedRSAPublicKey`].
    fn assign_public_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_key: RSAPublicKey<F>,
    ) -> Result<AssignedRSAPublicKey<F>, Error>;

    /// Assigns a [`AssignedRSASignature`].
    fn assign_signature(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<F>, Error>;

    /// Given a base `x`, a RSA public key (e,n), performs the modular power `x^e mod n`.
    fn modpow_public_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &AssignedInteger<F, Fresh>,
        public_key: &AssignedRSAPublicKey<F>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    /// Given a RSA public key, a message hashed with SHA256, and a pkcs1v15 signature, verifies the signature with the public key and the hashed messaged.
    fn verify_pkcs1v15_signature(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_key: &AssignedRSAPublicKey<F>,
        hashed_msg: &AssignedInteger<F, Fresh>,
        signature: &AssignedRSASignature<F>,
    ) -> Result<AssignedValue<F>, Error>;
}
