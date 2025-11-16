use criterion::{criterion_group, criterion_main, Criterion};
use plume_qe_core::{
    PlumeSession, PolymorphismEngine, PolymorphismIntensity, SecurityLevel,
    decrypt_payload_view, encrypt_payload, keygen_bundle_with_rng, payload::PayloadView,
    payload::PayloadOptions,
};
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    let profile = plume_qe_core::profile_phase1();
    group.bench_function("single-profile", |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = plume_qe_core::crypto::keygen_with_rng(&profile, &mut rng);
        })
    });
    group.bench_function("bundle-phase1", |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
            let engine = PolymorphismEngine::phase1();
            let _ = keygen_bundle_with_rng(engine.registry(), &mut rng);
        })
    });
}

fn bench_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("kem");
    let mut rng = OsRng;
    let engine = PolymorphismEngine::phase1();
    let bundle = keygen_bundle_with_rng(engine.registry(), &mut rng);
    let seed = b"bench-seed";
    group.bench_function("encaps", |b| {
        b.iter(|| {
            let _ = plume_qe_core::kem::encapsulate(&engine, &bundle.public, seed, 0).unwrap();
        })
    });
    let (kem, _) = plume_qe_core::kem::encapsulate(&engine, &bundle.public, seed, 0).unwrap();
    group.bench_function("decaps", |b| {
        b.iter(|| {
            let _ = plume_qe_core::kem::decapsulate(&engine, &bundle.secret, seed, 0, &kem)
                .unwrap();
        })
    });
}

fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");
    let mut rng = OsRng;
    let engine = PolymorphismEngine::phase1();
    let bundle = keygen_bundle_with_rng(engine.registry(), &mut rng);
    let seed = b"bench-seed";
    let options = PayloadOptions::cover_only(b"small data", b"aad");
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let _ = encrypt_payload(&engine, &bundle.public, seed, 0, options.clone(), b"ctx")
                .unwrap();
        })
    });
    let payload = encrypt_payload(&engine, &bundle.public, seed, 0, options, b"ctx").unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let _ = decrypt_payload_view(
                &engine,
                &bundle.secret,
                seed,
                0,
                &payload,
                b"ctx",
                PayloadView::Cover,
            )
            .unwrap();
        })
    });
}

fn bench_scheduler_graph(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler_graph");
    let engine = PolymorphismEngine::phase1();
    let seed = b"bench-seed";
    group.bench_function("scheduler_step", |b| {
        b.iter(|| {
            let _ = engine.scheduler().derive_trace(seed, 10, 3);
        })
    });
    group.bench_function("graph_walk", |b| {
        b.iter(|| {
            let _ = engine.graph().node_for_message(seed, 10);
        })
    });
}

fn bench_session_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_bytes");
    let mut rng = OsRng;
    let bundle = keygen_bundle_with_rng(PolymorphismEngine::phase1().registry(), &mut rng);
    let session = PlumeSession::new(SecurityLevel::Toy, PolymorphismIntensity::Medium, b"ctx");
    group.bench_function("encrypt_bytes", |b| {
        b.iter(|| {
            let _ = session
                .encrypt_bytes(&bundle.public, b"seed", 0, b"payload", b"aad")
                .unwrap();
        })
    });
    let payload = session
        .encrypt_bytes(&bundle.public, b"seed", 0, b"payload", b"aad")
        .unwrap();
    group.bench_function("decrypt_bytes", |b| {
        b.iter(|| {
            let _ = session
                .decrypt_bytes(&bundle.secret, b"seed", 0, &payload)
                .unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_kem,
    bench_aead,
    bench_scheduler_graph,
    bench_session_encrypt_decrypt
);
criterion_main!(benches);
