use crate::{
    big_integer::{
        BigIntChip, BigIntConfig, BigIntInstructions, Fresh, Muled, RangeType, RefreshAux,
        UnassignedInteger,
    },
    impl_pkcs1v15_basic_circuit, AssignedRSAPublicKey, AssignedRSASignature, RSAChip, RSAConfig,
    RSAInstructions, RSAPubE, RSAPublicKey, RSASignature, RSASignatureVerifier,
};
use halo2_dynamic_sha256::{Field, Sha256Chip, Sha256Config};
use halo2wrong::curves::bn256::{Bn256, Fr, G1Affine};
use halo2wrong::{
    curves::FieldExt,
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
            ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
        },
        poly::{
            commitment::{CommitmentScheme, Params},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
};
use js_sys::{JsString, Uint8Array};
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};
use num_bigint::BigUint;
use rand::{rngs::OsRng, thread_rng, Rng};
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::*;
use sha2::{Digest, Sha256};
use std::{fs::File, io::BufReader, marker::PhantomData};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_64WasmConfig,
    Pkcs1v15_1024_64WasmCircuit,
    setup_pkcs1v15_1024_64_wasm,
    prove_pkcs1v15_1024_64_wasm,
    17,
    1024,
    64,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_64WasmNoSha2Config,
    Pkcs1v15_1024_64WasmNoSha2Circuit,
    setup_pkcs1v15_1024_64_wasm_no_sha2,
    prove_pkcs1v15_1024_64_wasm_no_sha2,
    17,
    1024,
    64,
    false
);

/*#[derive(Debug, Clone)]
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
}*/
type RSAWasm<F> = Pkcs1v15_1024_64WasmCircuit<F>;
#[wasm_bindgen]
pub fn sample_rsa_private_key() -> JsValue {
    let mut rng = thread_rng();
    let private_key =
        RsaPrivateKey::new(&mut rng, RSAWasm::<Fr>::BITS_LEN).expect("failed to generate a key");
    serde_wasm_bindgen::to_value(&private_key).unwrap()
}

#[wasm_bindgen]
pub fn generate_rsa_public_key(private_key: JsValue) -> JsValue {
    let private_key: RsaPrivateKey = serde_wasm_bindgen::from_value(private_key).unwrap();
    let public_key = RsaPublicKey::from(private_key);
    serde_wasm_bindgen::to_value(&public_key).unwrap()
}

#[wasm_bindgen]
pub fn sign(private_key: JsValue, msg: JsValue) -> JsValue {
    let private_key: RsaPrivateKey = serde_wasm_bindgen::from_value(private_key).unwrap();
    //let msg: Vec<u8> = serde_wasm_bindgen::from_value(msg).unwrap();
    let msg: Vec<u8> = Uint8Array::new(&msg).to_vec();
    let hashed_msg = Sha256::digest(&msg);

    let padding = PaddingScheme::PKCS1v15Sign {
        hash: Some(Hash::SHA2_256),
    };
    let sign = private_key
        .sign(padding, &hashed_msg)
        .expect("fail to sign a hashed message.");
    serde_wasm_bindgen::to_value(&sign).unwrap()
}

#[wasm_bindgen]
pub fn sha256_msg(msg: JsValue) -> JsValue {
    //let msg: Vec<u8> = serde_wasm_bindgen::from_value(msg).unwrap();
    let msg: Vec<u8> = Uint8Array::new(&msg).to_vec();
    let hashed_msg = Sha256::digest(&msg).to_vec();
    serde_wasm_bindgen::to_value(&hashed_msg).unwrap()
}

#[wasm_bindgen]
pub fn prove_pkcs1v15_1024_128_circuit(
    params: JsValue,
    public_key: JsValue,
    msg: JsValue,
    signature: JsValue,
) -> JsValue {
    console_error_panic_hook::set_once();

    //let msg: Vec<u8> = serde_wasm_bindgen::from_value(msg).unwrap();
    let msg: Vec<u8> = Uint8Array::new(&msg).to_vec();
    let mut signature: Vec<u8> = serde_wasm_bindgen::from_value(signature).unwrap();
    let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key).unwrap();

    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();

    let limb_width = RSAWasm::<Fr>::LIMB_WIDTH;
    let num_limbs = RSAWasm::<Fr>::BITS_LEN / RSAWasm::<Fr>::LIMB_WIDTH;

    let hashed_msg = Sha256::digest(&msg);

    signature.reverse();
    let sign_big = BigUint::from_bytes_le(&signature);
    let sign_limbs = decompose_big::<Fr>(sign_big.clone(), num_limbs, limb_width);
    let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<Fr>(n_big.clone(), num_limbs, limb_width);
    let n_unassigned = UnassignedInteger::from(n_limbs.clone());
    let e_fix = RSAPubE::Fix(BigUint::from(RSAWasm::<Fr>::DEFAULT_E));
    let public_key = RSAPublicKey::new(n_unassigned, e_fix);

    // Compute the randomness from the hashed_msg.
    let mut seed = [0; 64];
    for idx in 0..32 {
        seed[idx] = hashed_msg[idx];
    }
    let r = <Fr as FieldExt>::from_bytes_wide(&seed);

    let circuit = RSAWasm::<Fr> {
        signature,
        public_key,
        msg,
        r,
        _f: PhantomData,
    };

    let mut column0_public_inputs = n_limbs;
    let mut hash_fes = hashed_msg
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect::<Vec<Fr>>();
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
    )
    .unwrap();
    let proof = transcript.finalize();
    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify_pkcs1v15_1024_128_circuit(
    params: JsValue,
    public_key: JsValue,
    hashed_msg: JsValue,
    proof: JsValue,
) -> bool {
    console_error_panic_hook::set_once();
    let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key).unwrap();
    let hashed_msg: Vec<u8> = serde_wasm_bindgen::from_value(hashed_msg).unwrap();

    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();
    let circuit = RSAWasm::<Fr>::default();
    let vk = keygen_vk(&params, &circuit).unwrap();

    let limb_width = RSAWasm::<Fr>::LIMB_WIDTH;
    let num_limbs = RSAWasm::<Fr>::BITS_LEN / RSAWasm::<Fr>::LIMB_WIDTH;
    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<Fr>(n_big.clone(), num_limbs, limb_width);
    let mut column0_public_inputs = n_limbs;
    let mut hash_fes = hashed_msg
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect::<Vec<Fr>>();
    column0_public_inputs.append(&mut hash_fes);

    let strategy = SingleStrategy::new(&params);
    let proof: Vec<u8> = serde_wasm_bindgen::from_value(proof).unwrap();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<_, VerifierGWC<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[&column0_public_inputs]],
        &mut transcript,
    )
    .is_ok()
}

type RSAWasmNoSha2<F> = Pkcs1v15_1024_64WasmNoSha2Circuit<F>;
#[wasm_bindgen]
pub fn prove_pkcs1v15_1024_128_circuit_no_sha2(
    params: JsValue,
    public_key: JsValue,
    hashed_msg: JsValue,
    signature: JsValue,
) -> JsValue {
    console_error_panic_hook::set_once();

    let mut signature: Vec<u8> = serde_wasm_bindgen::from_value(signature).unwrap();
    let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key).unwrap();

    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();

    let limb_width = RSAWasmNoSha2::<Fr>::LIMB_WIDTH;
    let num_limbs = RSAWasmNoSha2::<Fr>::BITS_LEN / RSAWasmNoSha2::<Fr>::LIMB_WIDTH;

    let hashed_msg: Vec<u8> = serde_wasm_bindgen::from_value(hashed_msg).unwrap();

    signature.reverse();
    let sign_big = BigUint::from_bytes_le(&signature);
    let sign_limbs = decompose_big::<Fr>(sign_big.clone(), num_limbs, limb_width);
    let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<Fr>(n_big.clone(), num_limbs, limb_width);
    let n_unassigned = UnassignedInteger::from(n_limbs.clone());
    let e_fix = RSAPubE::Fix(BigUint::from(RSAWasmNoSha2::<Fr>::DEFAULT_E));
    let public_key = RSAPublicKey::new(n_unassigned, e_fix);

    // Compute the randomness from the hashed_msg.
    let mut seed = [0; 64];
    for idx in 0..32 {
        seed[idx] = hashed_msg[idx];
    }
    let r = <Fr as FieldExt>::from_bytes_wide(&seed);

    let circuit = RSAWasmNoSha2::<Fr> {
        signature,
        public_key,
        msg: hashed_msg.clone(),
        r,
        _f: PhantomData,
    };

    let mut column0_public_inputs = n_limbs;
    let mut hash_fes = hashed_msg
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect::<Vec<Fr>>();
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
    )
    .unwrap();
    let proof = transcript.finalize();
    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify_pkcs1v15_1024_128_circuit_no_sha2(
    params: JsValue,
    public_key: JsValue,
    hashed_msg: JsValue,
    proof: JsValue,
) -> bool {
    console_error_panic_hook::set_once();
    let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key).unwrap();
    let hashed_msg: Vec<u8> = serde_wasm_bindgen::from_value(hashed_msg).unwrap();

    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();
    let circuit = RSAWasmNoSha2::<Fr>::default();
    let vk = keygen_vk(&params, &circuit).unwrap();

    let limb_width = RSAWasmNoSha2::<Fr>::LIMB_WIDTH;
    let num_limbs = RSAWasmNoSha2::<Fr>::BITS_LEN / RSAWasmNoSha2::<Fr>::LIMB_WIDTH;
    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<Fr>(n_big.clone(), num_limbs, limb_width);
    let mut column0_public_inputs = n_limbs;
    let mut hash_fes = hashed_msg
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect::<Vec<Fr>>();
    column0_public_inputs.append(&mut hash_fes);

    let strategy = SingleStrategy::new(&params);
    let proof: Vec<u8> = serde_wasm_bindgen::from_value(proof).unwrap();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<_, VerifierGWC<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[&column0_public_inputs]],
        &mut transcript,
    )
    .is_ok()
}
/*
mod tests {
    use std::{fs::File, io::Read};

    use super::*;
    use rand::{thread_rng, Rng};
    use rsa::{Hash, PaddingScheme, RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    #[test]
    fn write_params() {
        let mut file = File::create("params.bin").unwrap();
        let params = gen_srs(17);
        params.write(&mut file).unwrap();
        write_srs(17, "params.bin")
    }

    // #[wasm_bindgen_test]
    /*fn test_wasm() {
        let mut params_file = File::open("params.bin").unwrap();
        let mut params_buf = vec![];
        params_file.read_to_end(&mut params_buf);
        let params_js = serde_wasm_bindgen::to_value(&params_buf).unwrap();

        // 1. Uniformly sample a RSA key pair.
        let mut rng = thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, RSAWasm::<F>::BITS_LEN).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);
        // 2. Uniformly sample a message.
        let mut msg: [u8; 128] = [0; 128];
        for i in 0..128 {
            msg[i] = rng.gen();
        }
        // 3. Compute the SHA256 hash of `msg`.
        let hashed_msg = Sha256::digest(&msg);
        // 4. Generate a pkcs1v15 signature.
        let padding = PaddingScheme::PKCS1v15Sign {
            hash: Some(Hash::SHA2_256),
        };
        let mut sign = private_key
            .sign(padding, &hashed_msg)
            .expect("fail to sign a hashed message.");

        let msg_js = serde_wasm_bindgen::to_value(&msg.to_vec()).unwrap();
        let signature_js = serde_wasm_bindgen::to_value(&sign).unwrap();
        let public_key_js = serde_wasm_bindgen::to_value(&public_key).unwrap();

        // prove(params_js, msg_js, signature_js, public_key_js);
    }*/
}
*/
