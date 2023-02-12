use crate::{
    big_integer::{
        BigIntChip, BigIntConfig, BigIntInstructions, Fresh, Muled, RangeType, RefreshAux,
        UnassignedInteger,
    },
    impl_pkcs1v15_basic_circuit, AssignedRSAPublicKey, AssignedRSASignature, RSAChip, RSAConfig,
    RSAInstructions, RSAPubE, RSAPublicKey, RSASignature, RSASignatureVerifier,
};
use halo2_dynamic_sha256::{Field, Sha256BitConfig, Sha256DynamicChip, Sha256DynamicConfig};
use halo2wrong::curves::bn256::{Bn256, Fr, G1Affine};
use halo2wrong::{
    curves::FieldExt,
    halo2::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
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
        SerdeFormat,
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
use std::io::{BufReader, BufWriter, Write};
use std::{fs::File, marker::PhantomData};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_64EnabledBenchConfig,
    Pkcs1v15_1024_64EnabledBenchCircuit,
    setup_pkcs1v15_1024_64_enabled,
    prove_pkcs1v15_1024_64_enabled,
    15,
    1024,
    64,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_128EnabledBenchConfig,
    Pkcs1v15_1024_128EnabledBenchCircuit,
    setup_pkcs1v15_1024_128_enabled,
    prove_pkcs1v15_1024_128_enabled,
    15,
    1024,
    128,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_1024EnabledBenchConfig,
    Pkcs1v15_1024_1024EnabledBenchCircuit,
    setup_pkcs1v15_1024_1024_enabled,
    prove_pkcs1v15_1024_1024_enabled,
    16,
    1024,
    1024,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_2048_64EnabledBenchConfig,
    Pkcs1v15_2048_64EnabledBenchCircuit,
    setup_pkcs1v15_2048_64_enabled,
    prove_pkcs1v15_2048_64_enabled,
    17,
    2048,
    64,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_2048_128EnabledBenchConfig,
    Pkcs1v15_2048_128EnabledBenchCircuit,
    setup_pkcs1v15_2048_128_enabled,
    prove_pkcs1v15_2048_128_enabled,
    17,
    2048,
    128,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_2048_1024EnabledBenchConfig,
    Pkcs1v15_2048_1024EnabledBenchCircuit,
    setup_pkcs1v15_2048_1024_enabled,
    prove_pkcs1v15_2048_1024_enabled,
    17,
    2048,
    1024,
    true
);

#[wasm_bindgen]
pub fn sample_rsa_private_key(bits_len: usize) -> JsValue {
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits_len).expect("failed to generate a key");
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
    let hashed_msg = Sha256::digest(&msg).to_vec();

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

// #[wasm_bindgen]
// pub fn generate_pk_1024_64_circuit(params: JsValue) -> JsValue {
//     console_error_panic_hook::set_once();
//     let params = Uint8Array::new(&params).to_vec();
//     let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();
//     let circuit = Pkcs1v15_1024_64EnabledBenchCircuit::<Fr>::default();
//     let vk = keygen_vk(&params, &circuit).unwrap();
//     let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
//     let mut pk_bytes = Vec::new();
//     pk.write(&mut pk_bytes, SerdeFormat::RawBytes).unwrap();
//     serde_wasm_bindgen::to_value(&pk_bytes).unwrap()
// }

// #[wasm_bindgen]
// pub fn generate_vk_1024_64_circuit(params: JsValue) -> JsValue {
//     console_error_panic_hook::set_once();
//     let params = Uint8Array::new(&params).to_vec();
//     let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();
//     let circuit = Pkcs1v15_1024_64EnabledBenchCircuit::<Fr>::default();
//     let vk = keygen_vk(&params, &circuit).unwrap();
//     let mut vk_bytes = Vec::new();
//     vk.write(&mut vk_bytes, SerdeFormat::RawBytes).unwrap();
//     serde_wasm_bindgen::to_value(&vk_bytes).unwrap()
// }

#[wasm_bindgen]
pub fn prove_pkcs1v15_1024_64_circuit(
    params: JsValue,
    pk: JsValue,
    public_key: JsValue,
    msg: JsValue,
    signature: JsValue,
) -> JsValue {
    console_error_panic_hook::set_once();

    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();

    let pk: Vec<u8> = Uint8Array::new(&pk).to_vec();
    let pk = ProvingKey::<G1Affine>::read::<_, Pkcs1v15_1024_64EnabledBenchCircuit<Fr>>(
        &mut BufReader::new(&pk[..]),
        SerdeFormat::RawBytes,
    )
    .unwrap();

    let msg: Vec<u8> = Uint8Array::new(&msg).to_vec();
    let mut signature: Vec<u8> = serde_wasm_bindgen::from_value(signature).unwrap();
    let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key).unwrap();

    let limb_width = Pkcs1v15_1024_64EnabledBenchCircuit::<Fr>::LIMB_WIDTH;
    let num_limbs = Pkcs1v15_1024_64EnabledBenchCircuit::<Fr>::BITS_LEN
        / Pkcs1v15_1024_64EnabledBenchCircuit::<Fr>::LIMB_WIDTH;

    signature.reverse();
    let sign_big = BigUint::from_bytes_le(&signature);
    let sign_limbs = decompose_big::<Fr>(sign_big.clone(), num_limbs, limb_width);
    let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<Fr>(n_big.clone(), num_limbs, limb_width);
    let n_unassigned = UnassignedInteger::from(n_limbs.clone());
    let e_fix = RSAPubE::Fix(BigUint::from(
        Pkcs1v15_1024_64EnabledBenchCircuit::<Fr>::DEFAULT_E,
    ));
    let public_key = RSAPublicKey::new(n_unassigned, e_fix);

    let circuit = Pkcs1v15_1024_64EnabledBenchCircuit::<Fr> {
        signature,
        public_key,
        msg,
        _f: PhantomData,
    };

    let proof = {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[&[]]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };
    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify_pkcs1v15_1024_64_circuit(params: JsValue, vk: JsValue, proof: JsValue) -> bool {
    console_error_panic_hook::set_once();

    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();
    let vk: Vec<u8> = Uint8Array::new(&vk).to_vec();
    let vk = VerifyingKey::<G1Affine>::read::<_, Pkcs1v15_1024_64EnabledBenchCircuit<Fr>>(
        &mut BufReader::new(&vk[..]),
        SerdeFormat::RawBytes,
    )
    .unwrap();

    let strategy = SingleStrategy::new(&params);
    let proof: Vec<u8> = serde_wasm_bindgen::from_value(proof).unwrap();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<_, VerifierGWC<_>, _, _, _>(&params, &vk, strategy, &[&[&[]]], &mut transcript)
        .expect("proof invalid");
    true
}

#[wasm_bindgen]
pub fn prove_pkcs1v15_1024_1024_circuit(
    params: JsValue,
    pk: JsValue,
    public_key: JsValue,
    msg: JsValue,
    signature: JsValue,
) -> JsValue {
    console_error_panic_hook::set_once();

    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();

    let pk: Vec<u8> = Uint8Array::new(&pk).to_vec();
    let pk = ProvingKey::<G1Affine>::read::<_, Pkcs1v15_1024_1024EnabledBenchCircuit<Fr>>(
        &mut BufReader::new(&pk[..]),
        SerdeFormat::RawBytes,
    )
    .unwrap();

    let msg: Vec<u8> = Uint8Array::new(&msg).to_vec();
    let mut signature: Vec<u8> = serde_wasm_bindgen::from_value(signature).unwrap();
    let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key).unwrap();

    let limb_width = Pkcs1v15_1024_1024EnabledBenchCircuit::<Fr>::LIMB_WIDTH;
    let num_limbs = Pkcs1v15_1024_1024EnabledBenchCircuit::<Fr>::BITS_LEN
        / Pkcs1v15_1024_1024EnabledBenchCircuit::<Fr>::LIMB_WIDTH;

    signature.reverse();
    let sign_big = BigUint::from_bytes_le(&signature);
    let sign_limbs = decompose_big::<Fr>(sign_big.clone(), num_limbs, limb_width);
    let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<Fr>(n_big.clone(), num_limbs, limb_width);
    let n_unassigned = UnassignedInteger::from(n_limbs.clone());
    let e_fix = RSAPubE::Fix(BigUint::from(
        Pkcs1v15_1024_1024EnabledBenchCircuit::<Fr>::DEFAULT_E,
    ));
    let public_key = RSAPublicKey::new(n_unassigned, e_fix);

    let circuit = Pkcs1v15_1024_1024EnabledBenchCircuit::<Fr> {
        signature,
        public_key,
        msg,
        _f: PhantomData,
    };

    let proof = {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[&[]]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };
    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify_pkcs1v15_1024_1024_circuit(params: JsValue, vk: JsValue, proof: JsValue) -> bool {
    console_error_panic_hook::set_once();

    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();
    let vk: Vec<u8> = Uint8Array::new(&vk).to_vec();
    let vk = VerifyingKey::<G1Affine>::read::<_, Pkcs1v15_1024_1024EnabledBenchCircuit<Fr>>(
        &mut BufReader::new(&vk[..]),
        SerdeFormat::RawBytes,
    )
    .unwrap();

    let strategy = SingleStrategy::new(&params);
    let proof: Vec<u8> = serde_wasm_bindgen::from_value(proof).unwrap();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<_, VerifierGWC<_>, _, _, _>(&params, &vk, strategy, &[&[&[]]], &mut transcript)
        .expect("proof invalid");
    true
}
