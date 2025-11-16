//! RNG helpers distinguishing deterministic session PRFs and secure system RNG.
//!
//! PLUME-QE derives all session-specific randomness from the caller-provided
//! seed and message index using BLAKE3, feeding the result into `ChaCha20Rng`.
//! Noise sampling and key generation continue to rely on an OS-backed
//! `OsRng`, ensuring we clearly separate deterministic polymorphic control
//! from true entropy sources.

use blake3::Hasher;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Convenience alias for the OS-backed RNG used for keygen/noise sampling.
pub type SecureRng = OsRng;

/// Deterministic RNG derived from a session seed, message index, and label.
pub fn derive_session_rng(seed: &[u8], message_index: u64, label: &[u8]) -> ChaCha20Rng {
    let mut hasher = Hasher::new();
    hasher.update(seed);
    hasher.update(&message_index.to_le_bytes());
    hasher.update(label);
    let digest = hasher.finalize();
    let mut seed_material = [0u8; 32];
    seed_material.copy_from_slice(&digest.as_bytes()[..32]);
    ChaCha20Rng::from_seed(seed_material)
}

/// Fills `out` using deterministic session randomness for reproducible tests.
pub fn fill_session_bytes(seed: &[u8], message_index: u64, label: &[u8], out: &mut [u8]) {
    let mut rng = derive_session_rng(seed, message_index, label);
    rng.fill_bytes(out);
}

/// Helper that exposes a mutable secure RNG reference while documenting intent.
pub fn secure_rng() -> SecureRng {
    OsRng
}
