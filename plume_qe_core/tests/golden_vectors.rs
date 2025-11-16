use blake3;
use hex::encode as hex_encode;
use once_cell::sync::Lazy;
use plume_qe_core::context::mix_seed_with_fingerprint;
use plume_qe_core::crypto::{KeyPair, PolyKeyPair, keygen_bundle_with_rng, keygen_with_rng};
use plume_qe_core::kem::encapsulate;
use plume_qe_core::payload::{PayloadOptions, encrypt_payload};
use plume_qe_core::polymorph::PolymorphismEngine;
use plume_qe_core::profiles::{Profile, ProfileRegistry, profile_phase1};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::PathBuf;

static VECTOR_CASES: Lazy<Vec<VectorCase>> = Lazy::new(|| {
    vec![
        VectorCase::new("min_profile_ciphertext", vector_minimal_profile_ciphertext),
        VectorCase::new("chaotic_ciphertext", vector_chaotic_ciphertext),
        VectorCase::new("graph_walk", vector_graph_walk),
        VectorCase::new("kem_only", vector_kem_only),
        VectorCase::new("payload_file", vector_payload_file),
    ]
});

struct VectorCase {
    name: &'static str,
    generator: fn() -> Value,
}

impl VectorCase {
    const fn new(name: &'static str, generator: fn() -> Value) -> Self {
        Self { name, generator }
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("vectors")
            .join(format!("{}.json", self.name))
    }
}

#[test]
fn golden_vectors_match() {
    let update = env::var("PLUME_UPDATE_VECTORS").map_or(false, |v| v == "1");
    for case in VECTOR_CASES.iter() {
        let actual = (case.generator)();
        let path = case.path();
        if update {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, serde_json::to_string_pretty(&actual).unwrap()).unwrap();
        }
        let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "Missing golden vector '{}'. Run with PLUME_UPDATE_VECTORS=1 cargo test golden_vectors -- --nocapture to generate.",
                case.name
            )
        });
        let expected_value: Value = serde_json::from_str(&expected).unwrap();
        if expected_value != actual {
            panic!(
                "Golden vector '{}' drifted. Expected: {}\nActual: {}",
                case.name, expected_value, actual
            );
        }
    }
}

fn vector_minimal_profile_ciphertext() -> Value {
    let profile = profile_phase1();
    let keypair = deterministic_keypair(profile, b"phase5-min-keypair");
    let plaintext = b"PHASE5-MIN";
    let mut enc_rng = deterministic_rng(b"phase5-min-enc");
    let ciphertext = plume_qe_core::crypto::encrypt_with_profile(
        &profile,
        &keypair.public,
        plaintext,
        &mut enc_rng,
    )
    .expect("encrypt");
    json!({
        "description": "Minimal profile ciphertext",
        "plaintext_hex": hex_encode(plaintext),
        "profile_name": profile.name,
        "ciphertext": ciphertext,
    })
}

fn vector_chaotic_ciphertext() -> Value {
    let engine = PolymorphismEngine::phase1();
    let mut rng = deterministic_rng(b"phase5-chaotic-enc");
    let bundle = deterministic_bundle(b"phase5-chaotic-bundle", engine.registry());
    let seed = b"phase5-chaotic-seed";
    let fingerprint = b"phase5-chaotic-context";
    let seed_bytes = mix_seed_with_fingerprint(seed, fingerprint);
    let ciphertext = plume_qe_core::crypto::encrypt(
        &engine,
        &bundle.public,
        &seed_bytes,
        3,
        b"CHAOTIC-PLAIN",
        &mut rng,
    )
    .expect("encrypt chaotic");
    json!({
        "description": "Full chaotic ciphertext",
        "seed": String::from_utf8(seed.to_vec()).unwrap(),
        "fingerprint_hex": hex_encode(fingerprint),
        "message_index": 3,
        "ciphertext": ciphertext,
    })
}

fn vector_graph_walk() -> Value {
    let engine = PolymorphismEngine::phase1();
    let seed = b"phase5-graph-seed";
    let entries: Vec<_> = (0..8)
        .map(|i| {
            let node = engine.graph().node_for_message(seed, i);
            json!({
                "message_index": i,
                "node_id": node.id,
                "encoding": format!("{:?}", node.encoding),
                "profiles": node.profile_ids.iter().map(|p| p.0).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "description": "Graph-walk traversal",
        "seed": String::from_utf8(seed.to_vec()).unwrap(),
        "nodes": entries,
    })
}

fn vector_kem_only() -> Value {
    let engine = PolymorphismEngine::phase1();
    let bundle = deterministic_bundle(b"phase5-kem-bundle", engine.registry());
    let seed = b"phase5-kem-seed";
    let fingerprint = b"phase5-kem-context";
    let seed_bytes = mix_seed_with_fingerprint(seed, fingerprint);
    let (kem, shared_key) = encapsulate(&engine, &bundle.public, &seed_bytes, 5).unwrap();
    json!({
        "description": "KEM-only vector",
        "seed": String::from_utf8(seed.to_vec()).unwrap(),
        "message_index": 5,
        "fingerprint_hex": hex_encode(fingerprint),
        "kem": kem,
        "shared_key_hex": hex_encode(shared_key),
    })
}

fn vector_payload_file() -> Value {
    let engine = PolymorphismEngine::phase1();
    let bundle = deterministic_bundle(b"phase5-payload-bundle", engine.registry());
    let seed = b"phase5-payload-seed";
    let context = b"phase5-payload-context";
    let seed_bytes = mix_seed_with_fingerprint(seed, context);
    let options = PayloadOptions::cover_only(b"FILE-BYTES", b"AAD");
    let payload =
        encrypt_payload(&engine, &bundle.public, &seed_bytes, 7, options, context).unwrap();
    json!({
        "description": "KEM+AEAD payload",
        "seed": String::from_utf8(seed.to_vec()).unwrap(),
        "message_index": 7,
        "fingerprint_hex": hex_encode(context),
        "payload": payload,
    })
}

fn deterministic_bundle(seed: &[u8], registry: ProfileRegistry<'static>) -> PolyKeyPair {
    let mut rng = deterministic_rng(seed);
    keygen_bundle_with_rng(registry, &mut rng)
}

fn deterministic_keypair(profile: Profile, label: &[u8]) -> KeyPair {
    let mut rng = deterministic_rng(label);
    keygen_with_rng(&profile, &mut rng)
}

fn deterministic_rng(label: &[u8]) -> ChaCha20Rng {
    let hash = blake3::hash(label);
    ChaCha20Rng::from_seed(*hash.as_bytes())
}
