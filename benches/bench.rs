use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_base::halo2_proofs::poly::kzg::strategy::{AccumulatorStrategy, SingleStrategy};
use halo2_base::halo2_proofs::{
    circuit::{Cell, Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::Error,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Column, ConstraintSystem,
        Instance, ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
        },
        Rotation,
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
use halo2_rsa::{
    impl_pkcs1v15_basic_circuit, AssignedBigUint, AssignedRSAPubE, AssignedRSAPublicKey,
    AssignedRSASignature, BigUintConfig, BigUintInstructions, Fresh, RSAConfig, RSAInstructions,
    RSAPubE, RSAPublicKey, RSASignature, RSASignatureVerifier,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};
use rand::rngs::OsRng;
use std::marker::PhantomData;

use rand::{thread_rng, Rng};
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{prelude::*, BufReader, BufWriter},
    path::Path,
};

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
    Pkcs1v15_2048_3072EnabledBenchConfig,
    Pkcs1v15_2048_30720EnabledBenchCircuit,
    setup_pkcs1v15_2048_10240_enabled,
    prove_pkcs1v15_2048_10240_enabled,
    2048,
    10240,
    10,
    13,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_2048_1024DisabledBenchConfig,
    Pkcs1v15_2048DisabledBenchCircuit,
    setup_pkcs1v15_2048_1024_disabled,
    prove_pkcs1v15_2048_1024_disabled,
    2048,
    1024,
    1,
    13,
    false
);

fn save_params_pk_and_vk(
    params_filename: &str,
    pk_filename: &str,
    vk_filename: &str,
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    vk: &VerifyingKey<G1Affine>,
) {
    let f = File::create(params_filename).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();

    let f = File::create(pk_filename).unwrap();
    let mut writer = BufWriter::new(f);
    pk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
    writer.flush().unwrap();

    let f = File::create(vk_filename).unwrap();
    let mut writer = BufWriter::new(f);
    vk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
    writer.flush().unwrap();
}

fn bench_pkcs1v15_1024_enabled(c: &mut Criterion) {
    let mut group = c.benchmark_group("pkcs1v15, 1024 bit public key, sha2 enabled");
    group.sample_size(10);
    let (params, vk, pk) = setup_pkcs1v15_1024_64_enabled();
    save_params_pk_and_vk(
        "benches/params_1024_64.bin",
        "benches/1024_64.pk",
        "benches/1024_64.vk",
        &params,
        &pk,
        &vk,
    );
    group.bench_function("message 64 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_64_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_1024_128_enabled();
    save_params_pk_and_vk(
        "benches/params_1024_128.bin",
        "benches/1024_128.pk",
        "benches/1024_128.vk",
        &params,
        &pk,
        &vk,
    );
    group.bench_function("message 128 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_128_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_1024_1024_enabled();
    save_params_pk_and_vk(
        "benches/params_1024_1024.bin",
        "benches/1024_1024.pk",
        "benches/1024_1024.vk",
        &params,
        &pk,
        &vk,
    );
    group.bench_function("message 1024 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_1024_enabled(&params, &vk, &pk))
    });
    group.finish();
}

fn bench_pkcs1v15_2048_enabled(c: &mut Criterion) {
    let mut group = c.benchmark_group("pkcs1v15, 2048 bit public key, sha2 enabled");
    group.sample_size(10);
    let (params, vk, pk) = setup_pkcs1v15_2048_64_enabled();
    save_params_pk_and_vk(
        "benches/params_2048_64.bin",
        "benches/2048_64.pk",
        "benches/2048_64.vk",
        &params,
        &pk,
        &vk,
    );
    group.bench_function("message 64 bytes", |b| {
        b.iter(|| prove_pkcs1v15_2048_64_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_2048_128_enabled();
    save_params_pk_and_vk(
        "benches/params_2048_128.bin",
        "benches/2048_128.pk",
        "benches/2048_128.vk",
        &params,
        &pk,
        &vk,
    );
    group.bench_function("message 128 bytes", |b| {
        b.iter(|| prove_pkcs1v15_2048_128_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_2048_1024_enabled();
    save_params_pk_and_vk(
        "benches/params_2048_1024.bin",
        "benches/2048_1024.pk",
        "benches/2048_1024.vk",
        &params,
        &pk,
        &vk,
    );
    group.bench_function("message 1024 bytes", |b| {
        b.iter(|| prove_pkcs1v15_2048_1024_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_2048_10240_enabled();
    save_params_pk_and_vk(
        "benches/params_2048_10240.bin",
        "benches/2048_10240.pk",
        "benches/2048_10240.vk",
        &params,
        &pk,
        &vk,
    );
    group.bench_function("message 10240 bytes", |b| {
        b.iter(|| prove_pkcs1v15_2048_10240_enabled(&params, &vk, &pk))
    });
    group.finish();
}

fn bench_pkcs1v15_2048_disabled(c: &mut Criterion) {
    let mut group = c.benchmark_group("pkcs1v15, 2048 bit public key, sha2 disabled");
    group.sample_size(10);
    let (params, vk, pk) = setup_pkcs1v15_2048_1024_disabled();
    save_params_pk_and_vk(
        "benches/params_2048_1024_disable.bin",
        "benches/2048_1024_disable.pk",
        "benches/2048_1024_disable.vk",
        &params,
        &pk,
        &vk,
    );
    group.bench_function("message 1024 bytes", |b| {
        b.iter(|| prove_pkcs1v15_2048_1024_disabled(&params, &vk, &pk))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_pkcs1v15_1024_enabled,
    // bench_pkcs1v15_2048_enabled,
    // bench_pkcs1v15_2048_disabled
);
criterion_main!(benches);
