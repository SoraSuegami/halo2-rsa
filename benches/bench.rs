use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_dynamic_sha256::{Field, Sha256BitConfig, Sha256DynamicChip, Sha256DynamicConfig};
use halo2_rsa::{
    big_integer::{BigIntConfig, BigIntInstructions, UnassignedInteger},
    impl_pkcs1v15_basic_circuit, RSAChip, RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey,
    RSASignature, RSASignatureVerifier,
};
use halo2wrong::curves::bn256::{Bn256, Fr, G1Affine};
use halo2wrong::halo2::dev::MockProver;
use halo2wrong::{
    curves::FieldExt,
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
            ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
        },
        poly::{
            commitment::Params,
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
use maingate::{
    decompose_big, MainGate, MainGateInstructions, RangeChip, RangeInstructions, RegionCtx,
};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

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

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_64DisabledBenchConfig,
    Pkcs1v15_1024_64DisabledBenchCircuit,
    setup_pkcs1v15_1024_64_disabled,
    prove_pkcs1v15_1024_64_disabled,
    15,
    1024,
    64,
    false
);

fn bench_pkcs1v15_1024_enabled(c: &mut Criterion) {
    let mut group = c.benchmark_group("pkcs1v15, 1024 bit public key, sha2 enabled");
    group.sample_size(10);
    let (params, vk, pk) = setup_pkcs1v15_1024_64_enabled();
    group.bench_function("message 64 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_64_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_1024_128_enabled();
    group.bench_function("message 128 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_128_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_1024_1024_enabled();
    group.bench_function("message 1024 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_1024_enabled(&params, &vk, &pk))
    });
    group.finish();
}

fn bench_pkcs1v15_2048_enabled(c: &mut Criterion) {
    let mut group = c.benchmark_group("pkcs1v15, 2048 bit public key, sha2 enabled");
    group.sample_size(10);
    let (params, vk, pk) = setup_pkcs1v15_2048_64_enabled();
    group.bench_function("message 64 bytes", |b| {
        b.iter(|| prove_pkcs1v15_2048_64_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_2048_128_enabled();
    group.bench_function("message 128 bytes", |b| {
        b.iter(|| prove_pkcs1v15_2048_128_enabled(&params, &vk, &pk))
    });
    let (params, vk, pk) = setup_pkcs1v15_2048_1024_enabled();
    group.bench_function("message 1024 bytes", |b| {
        b.iter(|| prove_pkcs1v15_2048_1024_enabled(&params, &vk, &pk))
    });
    group.finish();
}

fn bench_pkcs1v15_1024_disabled(c: &mut Criterion) {
    let (params, vk, pk) = setup_pkcs1v15_1024_64_disabled();
    let mut group = c.benchmark_group("pkcs1v15, 1024 bit public key, sha2 disabled");
    group.sample_size(10);
    group.bench_function("message 64 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_64_disabled(&params, &vk, &pk))
    });
    group.finish();
}

criterion_group!(
    benches,
    //bench_pkcs1v15_1024_enabled,
    bench_pkcs1v15_2048_enabled,
    //bench_pkcs1v15_1024_disabled
);
criterion_main!(benches);
