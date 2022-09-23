use crate::{
    AssignedInteger, AssignedRSAPublicKey, AssignedRSASignature, Fresh, Muled, RSAPublicKey,
    RSASignature, RangeType, RefreshAux, UnassignedInteger,
};
use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use maingate::{AssignedValue, RegionCtx};
use num_bigint::BigUint;

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

    fn modpow_public_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &AssignedInteger<F, Fresh>,
        public_key: &AssignedRSAPublicKey<F>,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    fn verify_pkcs1v15_signature(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_key: &AssignedRSAPublicKey<F>,
        message: &[AssignedValue<F>],
        signature: &AssignedRSASignature<F>,
    ) -> Result<AssignedValue<F>, Error>;
}
