use criterion::{Criterion, black_box, criterion_group, criterion_main, measurement::WallTime};
use plume_qe_core::profiles::{paranoid_profiles, standard_profiles};
use plume_qe_core::{
    ChaoticScheduler, PlumeSession, PolyKeyPair, PolymorphismEngine, Profile, ProfileId,
    RingElement, SecurityLevel, decrypt_payload_view, encrypt_payload, keygen_bundle_with_rng,
    payload::PayloadOptions, payload::PayloadView, phase1_profiles, security_preset,
};
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::fs;
use tempfile::NamedTempFile;


struct FileBenchCtx {
    label: &'static str,
    session: PlumeSession,
    bundle: PolyKeyPair,
    seed: Vec<u8>,
    input: NamedTempFile,
    payload_enc: NamedTempFile,
    payload_dec: NamedTempFile,
    output: NamedTempFile,
}

const BENCH_FILE_BYTES: usize = 100 * 1024 * 1024;

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
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
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
            let _ =
                plume_qe_core::kem::decapsulate(&engine, &bundle.secret, seed, 0, &kem).unwrap();
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
            let _ =
                encrypt_payload(&engine, &bundle.public, seed, 0, options.clone(), b"ctx").unwrap();
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

fn bench_scheduler_step_fastpath(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler_step");
    let scheduler = ChaoticScheduler::default();
    let mut value = scheduler.derive_trace(b"bench-step", 0, 3).raw_value;
    group.bench_function("step", |b| {
        b.iter(|| {
            value = scheduler.step(value);
            black_box(value)
        })
    });
}

fn bench_session_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_bytes");
    let message = vec![0xAAu8; 4096];
    for level in SECURITY_LEVELS {
        let label = level_label(*level);
        let preset = security_preset(*level);
        let mut rng = ChaCha20Rng::from_seed(level_seed(*level, 0x10));
        let bundle = keygen_bundle_with_rng(preset.registry, &mut rng);
        let session = PlumeSession::new(*level, preset.default_intensity, b"bench-session");
        let seed = format!("bench-session-{label}");
        group.bench_function(format!("{label}::encrypt_bytes"), |b| {
            b.iter(|| {
                let payload = session
                    .encrypt_bytes(&bundle.public, seed.as_bytes(), 0, &message, b"bench-aad")
                    .unwrap();
                black_box(payload);
            })
        });
        let baseline = session
            .encrypt_bytes(&bundle.public, seed.as_bytes(), 0, &message, b"bench-aad")
            .unwrap();
        group.bench_function(format!("{label}::decrypt_bytes"), |b| {
            b.iter(|| {
                let payload = baseline.clone();
                let recovered = session
                    .decrypt_bytes(&bundle.secret, seed.as_bytes(), 0, &payload)
                    .unwrap();
                black_box(recovered);
            })
        });
    }
}

fn bench_ring_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_mul");
    let mut profiles: Vec<Profile> = Vec::new();
    profiles.extend_from_slice(phase1_profiles());
    profiles.extend_from_slice(standard_profiles());
    profiles.extend_from_slice(paranoid_profiles());
    for profile in profiles {
        bench_profile_ring_mul(&mut group, profile);
    }
}

fn bench_file_io(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_io");
    group.sample_size(10);
    let mut data = vec![0u8; BENCH_FILE_BYTES];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(31).wrapping_add(17);
    }
    let mut contexts = Vec::new();
    for level in SECURITY_LEVELS {
        let label = level_label(*level);
        let preset = security_preset(*level);
        let mut rng = ChaCha20Rng::from_seed(level_seed(*level, 0x30));
        let bundle = keygen_bundle_with_rng(preset.registry, &mut rng);
        let session = PlumeSession::new(*level, preset.default_intensity, b"bench-file");
        let input = NamedTempFile::new().expect("input file");
        fs::write(input.path(), &data).unwrap();
        let payload_enc = NamedTempFile::new().expect("payload enc");
        let payload_dec = NamedTempFile::new().expect("payload dec");
        let output = NamedTempFile::new().expect("output");
        contexts.push(FileBenchCtx {
            label,
            session,
            bundle,
            seed: format!("bench-file-{label}").into_bytes(),
            input,
            payload_enc,
            payload_dec,
            output,
        });
    }
    for ctx in &mut contexts {
        ctx.session
            .encrypt_file(
                &ctx.bundle.public,
                &ctx.seed,
                0,
                ctx.input.path(),
                ctx.payload_dec.path(),
            )
            .unwrap();
    }
    for ctx in &contexts {
        group.bench_function(format!("{}::encrypt_file_100mb", ctx.label), |b| {
            b.iter(|| {
                ctx.session
                    .encrypt_file(
                        &ctx.bundle.public,
                        &ctx.seed,
                        0,
                        ctx.input.path(),
                        ctx.payload_enc.path(),
                    )
                    .unwrap();
            })
        });
        group.bench_function(format!("{}::decrypt_file_100mb", ctx.label), |b| {
            b.iter(|| {
                ctx.session
                    .decrypt_file(
                        &ctx.bundle.secret,
                        &ctx.seed,
                        0,
                        ctx.payload_dec.path(),
                        ctx.output.path(),
                    )
                    .unwrap();
            })
        });
    }
}

fn bench_graph_full_walk(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_full_walk");
    let engine = PolymorphismEngine::phase1();
    let seed = b"bench-seed";
    group.bench_function("walk_64_messages", |b| {
        b.iter(|| {
            let node = engine.graph().walk_path(seed, 64);
            black_box(node.id)
        })
    });
}

fn bench_profile_ring_mul(group: &mut criterion::BenchmarkGroup<WallTime>, profile: Profile) {
    let mut rng = ChaCha20Rng::from_seed(profile_seed(profile.id));
    let a = RingElement::random_uniform(profile.ring, &mut rng);
    let b = RingElement::random_uniform(profile.ring, &mut rng);
    group.bench_function(format!("{}::schoolbook", profile.name), |bench| {
        bench.iter(|| {
            let res = a.mul_schoolbook(&b);
            black_box(res)
        });
    });
    if profile.ring.uses_ntt() {
        group.bench_function(format!("{}::ntt", profile.name), |bench| {
            bench.iter(|| {
                let res = a.mul_ntt(&b);
                black_box(res)
            });
        });
    }
}

fn profile_seed(id: ProfileId) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..2].copy_from_slice(&id.0.to_le_bytes());
    seed[2] = 1;
    seed
}

const SECURITY_LEVELS: &[SecurityLevel] = &[
    SecurityLevel::Toy,
    SecurityLevel::Standard,
    SecurityLevel::Paranoid,
];

fn level_label(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Toy => "toy",
        SecurityLevel::Standard => "standard",
        SecurityLevel::Paranoid => "paranoid",
    }
}

fn level_seed(level: SecurityLevel, salt: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = salt;
    seed[1] = match level {
        SecurityLevel::Toy => 0xA1,
        SecurityLevel::Standard => 0xB2,
        SecurityLevel::Paranoid => 0xC3,
    };
    seed
}

criterion_group!(
    benches,
    bench_keygen,
    bench_kem,
    bench_aead,
    bench_scheduler_graph,
    bench_session_encrypt_decrypt,
    bench_scheduler_step_fastpath,
    bench_ring_multiplication,
    bench_graph_full_walk,
    bench_file_io
);
criterion_main!(benches);
