use crate::{
    impl_pkcs1v15_basic_circuit, AssignedBigUint, AssignedRSAPubE, AssignedRSAPublicKey,
    AssignedRSASignature, BigUintConfig, BigUintInstructions, Fresh, RSAConfig, RSAInstructions,
    RSAPubE, RSAPublicKey, RSASignature, RSASignatureVerifier,
};
use halo2_base::halo2_proofs::{
    circuit::{Cell, Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, Circuit, Column, ConstraintSystem, Instance,
        ProvingKey, VerifyingKey,
    },
    plonk::{verify_proof, Error},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        Rotation, VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat,
};
use halo2_base::utils::fe_to_bigint;
use halo2_base::ContextParams;
use halo2_base::QuantumCell;
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context,
};
use halo2_dynamic_sha256::{Field, Sha256CompressionConfig, Sha256DynamicConfig};
use halo2_ecc::bigint::{
    big_is_equal, big_is_zero, big_less_than, carry_mod, mul_no_carry, negative, select, sub,
    CRTInteger, FixedCRTInteger, FixedOverflowInteger, OverflowInteger,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};
use rand::rngs::OsRng;
use std::marker::PhantomData;

use rand::{thread_rng, Rng};
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use js_sys::{Array, JsString, Uint8Array};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::*;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;
use web_sys::console::*;

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_64EnabledBenchConfig,
    Pkcs1v15_1024_64EnabledBenchCircuit,
    setup_pkcs1v15_1024_64_enabled,
    prove_pkcs1v15_1024_64_enabled,
    1024,
    64,
    1,
    13,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_128EnabledBenchConfig,
    Pkcs1v15_1024_128EnabledBenchCircuit,
    setup_pkcs1v15_1024_128_enabled,
    prove_pkcs1v15_1024_128_enabled,
    1024,
    128,
    1,
    13,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_1024EnabledBenchConfig,
    Pkcs1v15_1024_1024EnabledBenchCircuit,
    setup_pkcs1v15_1024_1024_enabled,
    prove_pkcs1v15_1024_1024_enabled,
    1024,
    1024,
    1,
    13,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_2048_64EnabledBenchConfig,
    Pkcs1v15_2048_64EnabledBenchCircuit,
    setup_pkcs1v15_2048_64_enabled,
    prove_pkcs1v15_2048_64_enabled,
    2048,
    64,
    1,
    13,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_2048_128EnabledBenchConfig,
    Pkcs1v15_2048_128EnabledBenchCircuit,
    setup_pkcs1v15_2048_128_enabled,
    prove_pkcs1v15_2048_128_enabled,
    2048,
    128,
    1,
    13,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_2048_1024EnabledBenchConfig,
    Pkcs1v15_2048_1024EnabledBenchCircuit,
    setup_pkcs1v15_2048_1024_enabled,
    prove_pkcs1v15_2048_1024_enabled,
    2048,
    1024,
    1,
    13,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_2048_1024DisabledBenchConfig,
    Pkcs1v15_2048_1024DisabledBenchCircuit,
    setup_pkcs1v15_2048_1024_disabled,
    prove_pkcs1v15_2048_1024_disabled,
    2048,
    1024,
    1,
    13,
    false
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

#[macro_export]
macro_rules! impl_pkcs1v15_wasm_functions {
    ($circuit_name:ident, $prove_fn_name:ident, $verify_fn_name:ident, $msg_len:expr, $k:expr, $sha2_chip_enabled:expr) => {
        #[wasm_bindgen]
        pub fn $prove_fn_name(
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
            let pk = ProvingKey::<G1Affine>::read::<_, $circuit_name<Fr>>(
                &mut BufReader::new(&pk[..]),
                SerdeFormat::RawBytes,
            )
            .unwrap();

            let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key).unwrap();
            let n_big =
                BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
            let e_fix = RSAPubE::Fix(BigUint::from($circuit_name::<Fr>::DEFAULT_E));
            let public_key = RSAPublicKey::new(Value::known(n_big), e_fix);

            let msg: Vec<u8> = Uint8Array::new(&msg).to_vec();
            let mut signature: Vec<u8> = serde_wasm_bindgen::from_value(signature).unwrap();

            signature.reverse();
            let sign_big = BigUint::from_bytes_le(&signature);
            let signature = RSASignature::new(Value::known(sign_big));

            let circuit = $circuit_name::<Fr> {
                signature,
                public_key,
                msg,
                _f: PhantomData,
            };

            let prover = match MockProver::run($k, &circuit, vec![]) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            prover.verify().unwrap();

            let proof = {
                let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
                create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
                    &params,
                    &pk,
                    &[circuit],
                    &[&[]],
                    OsRng,
                    &mut transcript,
                )
                .unwrap();
                transcript.finalize()
            };
            serde_wasm_bindgen::to_value(&proof).unwrap()
        }

        #[wasm_bindgen]
        pub fn $verify_fn_name(params: JsValue, vk: JsValue, proof: JsValue) -> bool {
            console_error_panic_hook::set_once();

            let params = Uint8Array::new(&params).to_vec();
            let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();
            let vk: Vec<u8> = Uint8Array::new(&vk).to_vec();
            let vk = VerifyingKey::<G1Affine>::read::<_, $circuit_name<Fr>>(
                &mut BufReader::new(&vk[..]),
                SerdeFormat::RawBytes,
            )
            .unwrap();

            let strategy = SingleStrategy::new(&params);
            let proof: Vec<u8> = serde_wasm_bindgen::from_value(proof).unwrap();
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            verify_proof::<_, VerifierGWC<_>, _, _, _>(
                &params,
                &vk,
                strategy,
                &[&[]],
                &mut transcript,
            )
            .expect("proof invalid");
            true
        }
    };
}

impl_pkcs1v15_wasm_functions!(
    Pkcs1v15_1024_64EnabledBenchCircuit,
    prove_pkcs1v15_1024_64_circuit,
    verify_pkcs1v15_1024_64_circuit,
    64,
    13,
    true
);

impl_pkcs1v15_wasm_functions!(
    Pkcs1v15_1024_128EnabledBenchCircuit,
    prove_pkcs1v15_1024_128_circuit,
    verify_pkcs1v15_1024_128_circuit,
    128,
    13,
    true
);

impl_pkcs1v15_wasm_functions!(
    Pkcs1v15_1024_1024EnabledBenchCircuit,
    prove_pkcs1v15_1024_1024_circuit,
    verify_pkcs1v15_1024_1024_circuit,
    1024,
    13,
    true
);

impl_pkcs1v15_wasm_functions!(
    Pkcs1v15_2048_64EnabledBenchCircuit,
    prove_pkcs1v15_2048_64_circuit,
    verify_pkcs1v15_2048_64_circuit,
    64,
    13,
    true
);

impl_pkcs1v15_wasm_functions!(
    Pkcs1v15_2048_128EnabledBenchCircuit,
    prove_pkcs1v15_2048_128_circuit,
    verify_pkcs1v15_2048_128_circuit,
    128,
    13,
    true
);

impl_pkcs1v15_wasm_functions!(
    Pkcs1v15_2048_1024EnabledBenchCircuit,
    prove_pkcs1v15_2048_1024_circuit,
    verify_pkcs1v15_2048_1024_circuit,
    1024,
    13,
    true
);

impl_pkcs1v15_wasm_functions!(
    Pkcs1v15_2048_1024DisabledBenchCircuit,
    prove_pkcs1v15_no_sha2_2048_1024_circuit,
    verify_pkcs1v15_no_sha2_2048_1024_circuit,
    1024,
    13,
    false
);

#[macro_export]
macro_rules! impl_pkcs1v15_wasm_multi_exec_bench {
    ($circuit_name:ident, $k:expr, $multi_bench_fn_name:ident) => {
        #[wasm_bindgen]
        pub fn $multi_bench_fn_name(
            params: JsValue,
            pk: JsValue,
            vk: JsValue,
            public_key: JsValue,
            msg: JsValue,
            signature: JsValue,
            times: usize,
        ) -> Array {
            let params = Uint8Array::new(&params).to_vec();
            let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).unwrap();
            let pk = Uint8Array::new(&pk).to_vec();
            let pk = ProvingKey::<G1Affine>::read::<_, $circuit_name<Fr>>(
                &mut BufReader::new(&pk[..]),
                SerdeFormat::RawBytes,
            )
            .unwrap();
            let vk = Uint8Array::new(&vk).to_vec();
            let vk = VerifyingKey::<G1Affine>::read::<_, $circuit_name<Fr>>(
                &mut BufReader::new(&vk[..]),
                SerdeFormat::RawBytes,
            )
            .unwrap();
            let public_key: RsaPublicKey = serde_wasm_bindgen::from_value(public_key).unwrap();
            let msg: Vec<u8> = Uint8Array::new(&msg).to_vec();
            let mut signature: Vec<u8> = serde_wasm_bindgen::from_value(signature).unwrap();
            signature.reverse();

            let (sum, square_sum) = (0..times)
                .into_par_iter()
                .map(|i| {
                    let window = web_sys::window().expect("should have a window in this context");
                    let performance = window
                        .performance()
                        .expect("performance should be available");
                    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16)
                        .unwrap();
                    let e_fix = RSAPubE::Fix(BigUint::from($circuit_name::<Fr>::DEFAULT_E));
                    let public_key = RSAPublicKey::new(Value::known(n_big), e_fix);
                    let msg = msg.to_vec();
                    let sign_big = BigUint::from_bytes_le(&signature);
                    let signature = RSASignature::new(Value::known(sign_big));

                    let circuit = $circuit_name::<Fr> {
                        signature,
                        public_key,
                        msg,
                        _f: PhantomData,
                    };

                    let prover = match MockProver::run($k, &circuit, vec![]) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e),
                    };
                    prover.verify().unwrap();

                    // log_2(&"start proof generation at".into(), &i.into());
                    let start = performance.timing().request_start();
                    let proof = {
                        let mut transcript =
                            Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
                        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
                            &params,
                            &pk,
                            &[circuit],
                            &[&[]],
                            OsRng,
                            &mut transcript,
                        )
                        .unwrap();
                        transcript.finalize()
                    };
                    let end = performance.timing().response_end();
                    // let strategy = SingleStrategy::new(&params);
                    // let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
                    // verify_proof::<_, VerifierGWC<_>, _, _, _>(
                    //     &params,
                    //     &vk,
                    //     strategy,
                    //     &[&[]],
                    //     &mut transcript,
                    // )
                    // .expect("proof invalid");
                    let sub = end - start;
                    // log_3(&"proof generation result ".into(), &i.into(), &sub.into());
                    (sub, sub * sub)
                })
                .reduce(
                    || (0.0f64, 0.0f64),
                    |results: (f64, f64), subs: (f64, f64)| {
                        (results.0 + subs.0, results.1 + subs.1)
                    },
                );
            let times = times as f64;
            let avg = sum / times;
            let square_avg = square_sum / times;
            let var = square_avg * square_avg - avg * avg;
            let sdv = var.sqrt();
            // let result = [JsValue::from_f64(avg), JsValue::from_f64(sdv)];
            let array = Array::new();
            array.set(0, JsValue::from_f64(avg));
            array.set(1, JsValue::from_f64(sdv));
            array
        }
    };
}

impl_pkcs1v15_wasm_multi_exec_bench!(
    Pkcs1v15_2048_1024EnabledBenchCircuit,
    13,
    multi_bench_2048_1024_circuit
);
