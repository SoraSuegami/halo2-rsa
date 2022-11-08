use crate::{
    big_integer::{
        AssignedInteger, BigIntChip, BigIntConfig, BigIntInstructions, Fresh, Muled, RangeType,
        RefreshAux, UnassignedInteger,
    },
    AssignedRSAPublicKey, AssignedRSASignature, Field, RSAChip, RSAConfig, RSAInstructions,
    RSAPubE, RSAPublicKey, RSASignature, RSASignatureVerifier, Sha256BitChip, Sha256BitConfig,
};
use halo2wrong::{
    curves::bn256::{Bn256, Fr as F, G1Affine},
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
        poly::{
            commitment::Params,
            kzg::commitment::ParamsKZG,
            kzg::{commitment::KZGCommitmentScheme, multiopen::ProverGWC},
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptReadBuffer,
            TranscriptWriterBuffer,
        },
    },
};
use js_sys::Uint8Array;
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rsa::{PublicKeyParts, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::{io::BufReader, marker::PhantomData, ops::SubAssign};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

#[derive(Debug, Clone)]
struct RSAWasmConfig<F: Field> {
    rsa_config: RSAConfig,
    sha256_config: Sha256BitConfig<F>,
}

struct RSAWasm<F: Field> {
    signature: RSASignature<F>,
    public_key: RSAPublicKey<F>,
    msg: Vec<u8>,
    _f: PhantomData<F>,
}

impl<F: Field> RSAWasm<F> {
    const BITS_LEN: usize = 2048;
    const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH;
    const EXP_LIMB_BITS: usize = 5;
    const DEFAULT_E: u128 = 65537;
    fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
        RSAChip::new(config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
    }
    fn sha256_chip(&self, config: Sha256BitConfig<F>) -> Sha256BitChip<F> {
        Sha256BitChip::new(config)
    }
}

impl<F: Field> Circuit<F> for RSAWasm<F> {
    type Config = RSAWasmConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // 1. Configure `MainGate`.
        let main_gate_config = MainGate::<F>::configure(meta);
        // 2. Compute bit length parameters by calling `RSAChip::<F>::compute_range_lens` function.
        let (composition_bit_lens, overflow_bit_lens) =
            RSAChip::<F>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH);
        // 3. Configure `RangeChip`.
        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        // 4. Configure `BigIntConfig`.
        let bigint_config = BigIntConfig::new(range_config, main_gate_config);
        // 5. Configure `RSAConfig`.
        let rsa_config = RSAConfig::new(bigint_config);
        // 6. Configure `Sha256BitConfig`.
        let sha256_config = Sha256BitConfig::<F>::configure(meta);
        Self::Config {
            rsa_config,
            sha256_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        let rsa_chip = self.rsa_chip(config.rsa_config);
        let sha256_chip = self.sha256_chip(config.sha256_config);
        let bigint_chip = rsa_chip.bigint_chip();
        let main_gate = rsa_chip.main_gate();
        let limb_width = Self::LIMB_WIDTH;
        let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
        // 1. Assign a public key and signature.
        let (public_key, signature) = layouter.assign_region(
            || "rsa signature with hash test using 2048 bits public keys",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let sign = rsa_chip.assign_signature(ctx, self.signature.clone())?;
                let public_key = rsa_chip.assign_public_key(ctx, self.public_key.clone())?;
                Ok((public_key, sign))
            },
        )?;
        // 2. Create a RSA signature verifier from `RSAChip` and `Sha256BitChip`
        let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
        // 3. Receives the verification result and the resulting hash of `self.msg` from `RSASignatureVerifier`.
        let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
            layouter.namespace(|| "verify pkcs1v15 signature"),
            &public_key,
            &self.msg,
            &signature,
        )?;
        // 4. Expose the RSA public key as public input.
        for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
            main_gate.expose_public(
                layouter.namespace(|| format!("expose {} th public key limb", i)),
                limb.assigned_val(),
                i,
            )?;
        }
        let num_limb_n = Self::BITS_LEN / RSAChip::<F>::LIMB_WIDTH;
        // 5. Expose the resulting hash as public input.
        for (i, val) in hashed_msg.into_iter().enumerate() {
            main_gate.expose_public(
                layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                val,
                num_limb_n + i,
            )?;
        }
        // 6. The verification result must be one.
        layouter.assign_region(
            || "assert is_valid==1",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                main_gate.assert_one(ctx, &is_valid)?;
                Ok(())
            },
        )?;
        // Create lookup tables for range check in `range_chip`.
        let range_chip = bigint_chip.range_chip();
        range_chip.load_table(&mut layouter)?;
        Ok(())
    }
}

fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

#[wasm_bindgen]
pub fn prove(params_js: JsValue, msg_js: JsValue, signature_js: JsValue, public_key_js: JsValue) {
    let msg: Vec<u8> = serde_wasm_bindgen::from_value(msg_js).unwrap();
    let mut sign: Vec<u8> = serde_wasm_bindgen::from_value(signature_js).unwrap();
    let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key_js).unwrap();

    let params = Uint8Array::new(&params_js).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();

    let limb_width = RSAWasm::<F>::LIMB_WIDTH;
    let num_limbs = RSAWasm::<F>::BITS_LEN / RSAWasm::<F>::LIMB_WIDTH;

    let hashed_msg = Sha256::digest(&msg);

    sign.reverse();
    let sign_big = BigUint::from_bytes_le(&sign);
    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
    let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
    let n_unassigned = UnassignedInteger::from(n_limbs.clone());
    let e_fix = RSAPubE::Fix(BigUint::from(RSAWasm::<F>::DEFAULT_E));
    let public_key = RSAPublicKey::new(n_unassigned, e_fix);

    let circuit = RSAWasm::<F> {
        signature,
        public_key,
        msg: msg.to_vec(),
        _f: PhantomData,
    };

    let n_fes = n_limbs;
    let mut hash_fes = hashed_msg
        .iter()
        .map(|byte| F::from(*byte as u64))
        .collect::<Vec<F>>();
    let mut column0_public_inputs = n_fes;
    column0_public_inputs.append(&mut hash_fes);

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[column0_public_inputs.as_slice()]],
        OsRng,
        &mut transcript,
    );
}

// #[wasm_bindgen]

// pub fn verify(params: JsValue) {}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use super::*;
    use rand::{thread_rng, Rng};
    use rsa::{Hash, PaddingScheme, RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;
    use wasm_bindgen_test::*;

    #[test]
    fn write_params() {
        let mut file = File::create("params.bin").unwrap();
        let params = gen_srs(17);
        params.write(&mut file).unwrap();
    }

    // #[wasm_bindgen_test]
    // fn test_wasm() {
    //     let mut params_file = File::open("params.bin").unwrap();
    //     let mut params_buf = vec![];
    //     params_file.read_to_end(&mut params_buf);
    //     let params_js = serde_wasm_bindgen::to_value(&params_buf).unwrap();

    //     // 1. Uniformly sample a RSA key pair.
    //     let mut rng = thread_rng();
    //     let private_key =
    //         RsaPrivateKey::new(&mut rng, RSAWasm::<F>::BITS_LEN).expect("failed to generate a key");
    //     let public_key = RsaPublicKey::from(&private_key);
    //     // 2. Uniformly sample a message.
    //     let mut msg: [u8; 128] = [0; 128];
    //     for i in 0..128 {
    //         msg[i] = rng.gen();
    //     }
    //     // 3. Compute the SHA256 hash of `msg`.
    //     let hashed_msg = Sha256::digest(&msg);
    //     // 4. Generate a pkcs1v15 signature.
    //     let padding = PaddingScheme::PKCS1v15Sign {
    //         hash: Some(Hash::SHA2_256),
    //     };
    //     let mut sign = private_key
    //         .sign(padding, &hashed_msg)
    //         .expect("fail to sign a hashed message.");

    //     let msg_js = serde_wasm_bindgen::to_value(&msg.to_vec()).unwrap();
    //     let signature_js = serde_wasm_bindgen::to_value(&sign).unwrap();
    //     let public_key_js = serde_wasm_bindgen::to_value(&public_key).unwrap();

    //     // prove(params_js, msg_js, signature_js, public_key_js);
    // }
}
