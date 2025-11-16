# PLUME-QE Phase 4 (Experimental)

PLUME-QE is a research-grade polymorphic lattice encryption prototype. Phase 4
adds a chaotic scheduler, a graph-walk mode selector, a KEM/AEAD stack, context
fingerprints, and a full CLI. **Nothing here is production-secure.**

## Highlights

- Logistic-map scheduler + deterministic graph walk over profile subsets.
- Polymorphic KEM layer with versioned `KemCiphertext` artifacts.
- ChaCha20-Poly1305 AEAD with deterministic nonces derived from the chaotic
  trace and context fingerprint.
- JSON serialization (with version tagging) for bundles, ciphertexts, KEMs, and
  AEAD payloads.
- Context fingerprints mixed into every session seed (either `--context` or the
  host's OS/arch/hostname signature).
- CLI operations: keygen, KEM encaps/decaps, message encrypt/decrypt, file
  encrypt/decrypt, and the legacy demo with scheduler overrides and debug logs.

## Workspace Layout

- `plume_qe_core/` – rings, profiles, chaotic scheduler, graph walk, KEM, AEAD,
  payload helpers, and tests.
- `plume_qe_demo/` – the `plume-qe` CLI which drives the core crate.

## Building & Testing

```
cargo build
cargo test
```

## CLI Overview

All commands accept optional global flags:

- `--security-level {toy|standard|paranoid}` – selects profile sets, scheduler defaults,
  and multi-view defaults.
- `--intensity {low|medium|high}` – adjusts the chaotic scheduler/graph traversal stride.
- `--context STRING` – override the context fingerprint (otherwise hostname/OS/arch are used).
- `--scheduler-mu` / `--scheduler-precision` – tweak the chaotic scheduler.
- `--debug` – enable detailed logging (graph node, profile, scheduler trace, etc.).
- Summary logs (when `--debug`) include scheduler mode, graph node IDs, profile IDs,
  and selection metadata; CI can scrape this output to ensure determinism.

### Key Generation

```
cargo run -p plume_qe_demo -- keygen --out keys.json
```

### KEM Encapsulation

```
cargo run -p plume_qe_demo -- kem-encaps \
  --keys keys.json \
  --seed "phase4-session" \
  --index 0 \
  --out kem.json
```

### KEM Decapsulation

```
cargo run -p plume_qe_demo -- kem-decaps \
  --keys keys.json \
  --seed "phase4-session" \
  --index 0 \
  --kem kem.json
```

### Message Encryption / Decryption

```
cargo run -p plume_qe_demo -- encrypt \
  --keys keys.json \
  --seed "phase4-session" \
  --index 1 \
  --message "hello PLUME" \
  --out ct.json

cargo run -p plume_qe_demo -- decrypt \
  --keys keys.json \
  --seed "phase4-session" \
  --index 1 \
  --cipher ct.json
```

Use `--input file.bin` instead of `--message` to encrypt arbitrary bytes.
Omit `--out` during decrypt to print to stdout.

### File Encryption / Decryption

```
cargo run -p plume_qe_demo -- encrypt-file \
  --keys keys.json \
  --seed "phase4-session" \
  --index 7 \
  --input plaintext.bin \
  --out payload.json \
  --enable-multiview \
  --cover-file harmless.txt

cargo run -p plume_qe_demo -- decrypt-file \
  --keys keys.json \
  --seed "phase4-session" \
  --index 7 \
  --cipher payload.json \
  --out recovered.bin \
  --decrypt-inner
```

`payload.json` contains a versioned `EncryptedPayload` tying together the KEM
ciphertext, AEAD layers (cover + optional inner), AAD, and fingerprint tag.
Use `--decrypt-cover` (default) or `--decrypt-inner` to select the layer to
recover.

### Legacy Demo

```
cargo run -p plume_qe_demo -- demo --seed "phase4-session" --count 3 --debug
```

The demo prints each message's graph node, profile, submode bits, and chaotic
value while performing encrypt/decrypt round-trips.

## Golden Test Vectors

Deterministic reference outputs live in `plume_qe_core/tests/vectors/*.json`.
Regenerate (when intentionally changing behavior) via:

```
PLUME_UPDATE_VECTORS=1 cargo test golden_vectors -- --nocapture
```

The regression test `golden_vectors_match` compares live outputs against the
stored JSON and fails if anything drifts.

## CI & Fuzzing

- A sample CI workflow lives at `.github/workflows/ci.yml` (fmt, clippy, `cargo test`,
  golden vector regression, bench smoke) with a placeholder fuzz harness step run
  in \"best effort\" mode.
- The placeholder fuzz harness (`plume_qe_core/tests/fuzz_harness.rs`) performs
  randomized encrypt/decrypt smoke tests for local experimentation; integrate a
  proper fuzzing engine (AFL/libFuzzer) as future work.

## High-Level API (`PlumeSession`)

Developers can integrate directly via the high-level `PlumeSession` API instead
of invoking the CLI. Example (encrypt/decrypt bytes):

```rust
use plume_qe_core::{
    keygen_bundle, PlumeSession, PolymorphismIntensity, SecurityLevel, PayloadView,
};

let bundle = keygen_bundle(plume_qe_core::profiles::ProfileRegistry::phase1());
let session = PlumeSession::new(SecurityLevel::Toy, PolymorphismIntensity::Medium, b"context");
let payload = session.encrypt_bytes(&bundle.public, b"seed", 0, b"hello", b"aad")?;
let recovered = session.decrypt_bytes(&bundle.secret, b"seed", 0, &payload)?;
assert_eq!(recovered, b"hello");
```

`encrypt_file` / `decrypt_file` mirror this behavior and operate on paths,
automatically following the security-level defaults (e.g., multi-view payloads
for `--security-level standard|paranoid`).

See `docs/api_overview.md` for the full stable API surface (types, error model,
serialization notes).

## Phase-4 Spec Addendum

- **Chaotic Scheduler** – logistic map (`μ` default 3.99) with 48-bit fixed-point
  precision. Seeds + message indices flow through the scheduler to obtain a raw
  value, slot index, and submode bits.
- **Graph Walk** – a static 3-node directed graph whose nodes reference profile
  subsets and encoding variants. `(seed, msg_index)` drive deterministic
  traversal along allowed edges.
- **KEM Layer** – uses the polymorphic PKE internally, emits a versioned
  `KemCiphertext` (profile id, submode bits, chaotic state) and a 256-bit shared
  secret derived from the ciphertext/context.
- **AEAD Layer** – ChaCha20-Poly1305 with nonces derived from `(seed, msg_index,
  chaos trace, fingerprint tag)`. Versioned payloads store the KEM ciphertext,
  nonce, ciphertext, and fingerprint tag. Multi-view payloads store a cover
  layer and optional inner layer plus a `has_inner_view` flag.
- **Context Fingerprints** – CLI collects the `--context` string or hashes
  hostname + OS + arch. This fingerprint is mixed into every session seed and
  validated against payload tags.
- **Serialization Versioning** – public bundles, secret bundles, KEM
  ciphertexts, direct ciphertexts, and payloads all carry explicit version
  fields checked during deserialization. `version_major = 1`, `version_minor = 0`
  are frozen for Phase-6; golden vectors fail if wire formats drift.
- **Side-Channel Hygiene** – integrity/fingerprint comparisons use constant-time
  checks; secret material (secret keys, shared/shared AEAD keys, fingerprints) is
  zeroized on drop using the `zeroize` policy.

### IND Game Definitions (Informal)

The following games guide testing/documentation (all parameters toy-sized):

1. **IND-CPA (Single Profile)** – Challenger samples `(pk, sk)` from a fixed profile,
   adversary outputs two equal-length messages, challenger encrypts one (uniform bit)
   and adversary must guess the bit. Our `encrypt_with_profile` API and the
   `min_profile_ciphertext` vector capture this experiment.
2. **IND-CPA (Polymorphic)** – Same as above but the challenger derives a profile via
   the chaotic scheduler/graph walk (seed + message index). The `chaotic_ciphertext`
   vector documents the deterministic execution path.
3. **IND-KEM** – Challenger generates a polymorphic bundle, adversary receives `pk`
   and outputs two strings; challenger encapsulates one, returns `(kem_ct, shared_key)`.
   Adversary must guess which shared key was chosen. KEM tests + vectors exercise this.
4. **IND-KEM+AEAD (Multi-View)** – Challenger additionally encrypts cover + optional
   inner payloads. Adversary obtains payload metadata (including `has_inner_view`) but
   must distinguish which plaintext was used in the selected layer.

### Payload JSON Schema

```
{
  "version": 1,
  "kem": { ... },
  "cover_layer": {
    "nonce": [12 bytes],
    "ciphertext": "base64/bytes",
    "aad": "base64/bytes"
  },
  "inner_layer": {
    "nonce": [12 bytes],
    "ciphertext": [...],
    "aad": [...]
  } | null,
  "has_inner_view": true|false,
  "fingerprint_tag": [32 bytes]
}
```

All numeric byte arrays are serialized as JSON arrays in the golden vectors. Future
versions must bump `version` and extend the schema without breaking older payloads.

### Security-Level Presets & Parameters

| Level     | Profiles `(n, q)`                                    | Noise | Scheduler (`μ`, precision) | Default Multi-View |
|-----------|-------------------------------------------------------|-------|----------------------------|--------------------|
| `toy`     | `(16, 2^16)`, `(32, 2^16)`, `(16, 2^17)`              | 3–5   | `3.90`, `40` bits          | Cover only         |
| `standard`| `(32, 2^17)`, `(32, 3·2^16)`                          | 4–5   | `3.97`, `48` bits          | Cover + optional inner |
| `paranoid`| `(48, 2^18)`, `(64, 2^19)`, `(64, 3·2^19)`            | 6–8   | `3.99`, `54` bits          | Always dual-layer  |

`--security-level` (CLI) and `PlumeSession::new` load these presets, which also
control the profile registry used by the chaotic scheduler.

### Polymorphism Intensity

`--intensity {low, medium, high}` alters how aggressively the scheduler/graph walk
advance:

- `low` – every message index considered; stable paths.
- `medium` (default) – scheduler steps twice per external message index.
- `high` – scheduler steps 4× per message, maximizing profile churn.

### Diagram References

While this README cannot embed full diagrams, the code implements the following
flows (see `plume_qe_core/src/{scheduler,graph,kem,payload}.rs`):

1. **Scheduler Loop** – `seed → derive_trace → slot/submode`.
2. **Graph Walk** – `trace.slot → node → profile subset`.
3. **KEM+AEAD Pipeline** – `keygen_bundle → KEM encaps → cover AEAD → inner AEAD`.

### Benchmark Notes

`cargo bench` runs the Criterion suite (`benches/core_bench.rs`) covering keygen,
KEM, AEAD, scheduler, and `PlumeSession` helpers. Criterion stores HTML reports
under `target/criterion/` – inspect `report/index.html` after running for local
performance snapshots.

### Security Notes

- Parameters are intentionally tiny (research/demo only); no post-quantum
  guarantees.
- Implementation is not constant-time and leaks timing/branch information.
- Multi-view payloads do not attempt steganographic cover; they merely provide
  dual plaintext slots bound to the same KEM.
- Context fingerprints use host metadata; treat them as debug aids, not
  authentication.

## Security Warning

This implementation is intentionally small, slow, and **NOT** hardened against
side channels. It should only be used to explore the PLUME-QE concepts.
