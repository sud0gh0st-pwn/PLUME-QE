# PLUME-QE Stable API (Phase 6)

This document summarizes the stable public API surface exposed by the `plume_qe_core`
crate. All functions/types described here are considered frozen for Phase-6.

## Key Types

- `ContextFingerprint` – wrapper around caller-provided context material; zeroized on drop.
- `KeyBundle` (`type KeyBundle = PolyKeyPair`) – polymorphic keypair bundle (public + secret).
- `KemCiphertext` – deterministic serialization of the polymorphic KEM.
- `PlumePayload` (`type PlumePayload = EncryptedPayload`) – multi-view payload format.
- `PlumeSession` – high-level session for encrypting bytes/files with presets.
- `PlumeError` / `PlumeSessionError` – stable error enums for low-level/high-level APIs.

## Key Functions

```rust
use plume_qe_core::{
    keygen_bundle, PolymorphismIntensity, PlumeSession, SecurityLevel,
    ContextFingerprint, PayloadView,
};

let bundle = keygen_bundle(plume_qe_core::profiles::ProfileRegistry::phase1());
let session = PlumeSession::new(
    SecurityLevel::Standard,
    PolymorphismIntensity::Medium,
    ContextFingerprint::from_str("demo"),
);
let payload = session.encrypt_bytes(&bundle.public, b"seed", 0, b"hello", b"aad")?;
let recovered = session.decrypt_bytes(&bundle.secret, b"seed", 0, &payload)?;
```

### Functions

- `keygen(profile)` – single-profile key generation.
- `keygen_bundle(registry)` – returns a `KeyBundle` for all profiles in a registry.
- `encrypt_bytes/decrypt_bytes` – high-level session helpers.
- `encrypt_file/decrypt_file` – file-based helpers.
- `mix_seed_with_fingerprint` – deterministic seed mixing.

## Serialization

- All exported types include `version` fields (`version_major = 1`). Any change requires bump and golden-vector update.
- `KemCiphertext`, `PlumePayload`, and `KeyBundle` serialization is tested via `tests/golden_vectors.rs`.

## Error Model

- `PlumeError` is returned by low-level APIs.
- `PlumeSessionError` wraps `PlumeError`, `std::io::Error`, and `serde_json::Error` for high-level helpers.

Refer to `README.md` for CLI usage and to the Rustdoc (`cargo doc --open`) for detailed type/function documentation.
