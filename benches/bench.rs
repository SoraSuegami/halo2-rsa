use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_dynamic_sha256::{Sha256Chip, Sha256Config, Table16Chip};
use halo2_rsa::{
    big_integer::{BigIntConfig, BigIntInstructions, UnassignedInteger},
    impl_pkcs1v15_basic_circuit, RSAChip, RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey,
    RSASignature, RSASignatureVerifier,
};
use halo2wrong::{
    curves::FieldExt,
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
            ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
        },
        poly::{
            commitment::CommitmentScheme,
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
use std::marker::PhantomData;

use halo2wrong::curves::bn256::{Bn256, Fr, G1Affine};
use halo2wrong::halo2::dev::MockProver;
use rand::{thread_rng, Rng};
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_64EnabledBenchConfig,
    Pkcs1v15_1024_64EnabledBenchCircuit,
    setup_pkcs1v15_1024_64_enabled,
    prove_pkcs1v15_1024_64_enabled,
    17,
    1024,
    64,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_128EnabledBenchConfig,
    Pkcs1v15_1024_128EnabledBenchCircuit,
    setup_pkcs1v15_1024_128_enabled,
    prove_pkcs1v15_1024_128_enabled,
    18,
    1024,
    128,
    true
);

impl_pkcs1v15_basic_circuit!(
    Pkcs1v15_1024_64DisabledBenchConfig,
    Pkcs1v15_1024_64DisabledBenchCircuit,
    setup_pkcs1v15_1024_64_disabled,
    prove_pkcs1v15_1024_64_disabled,
    16,
    1024,
    64,
    false
);

fn bench_pkcs1v15_1024_enabled(c: &mut Criterion) {
    let (params_64, vk_64, pk_64) = setup_pkcs1v15_1024_64_enabled();
    let (params_128, vk_128, pk_128) = setup_pkcs1v15_1024_128_enabled();
    let mut group = c.benchmark_group("pkcs1v15, 1024 bit public key, sha2 enabled");
    group.sample_size(10);
    group.bench_function("message 64 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_64_enabled(&params_64, &vk_64, &pk_64))
    });
    group.bench_function("message 128 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_128_enabled(&params_128, &vk_128, &pk_128))
    });
    group.finish();
}

fn bench_pkcs1v15_1024_disabled(c: &mut Criterion) {
    let (params_64, vk_64, pk_64) = setup_pkcs1v15_1024_64_disabled();
    let mut group = c.benchmark_group("pkcs1v15, 1024 bit public key, sha2 disabled");
    group.sample_size(10);
    group.bench_function("message 64 bytes", |b| {
        b.iter(|| prove_pkcs1v15_1024_64_disabled(&params_64, &vk_64, &pk_64))
    });
    group.finish();
}

criterion_group!(
    benches,
    //bench_pkcs1v15_1024_enabled,
    bench_pkcs1v15_1024_disabled
);
criterion_main!(benches);
