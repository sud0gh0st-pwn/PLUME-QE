//! Core types and primitives for the experimental PLUME-QE MVP.
//!
//! The implementation intentionally favors clarity over performance
//! and should **not** be used for production security.

pub mod aead;
pub mod context;
pub mod crypto;
pub mod graph;
pub mod kem;
pub mod payload;
pub mod polymorph;
pub mod preset;
pub mod profiles;
pub mod ring;
pub mod rng;
pub mod scheduler;
pub mod session;
pub mod versioning;

pub use crate::context::{ContextFingerprint, fingerprint_tag, mix_seed_with_fingerprint};
pub use crate::crypto::{
    Ciphertext, CiphertextBlock, KeyPair, PlumeError, PolyKeyPair, PolyPublicKey, PolySecretKey,
    PublicKey, SecretKey, decrypt, decrypt_with_profile, encrypt, encrypt_with_profile, keygen,
    keygen_bundle, keygen_bundle_with_rng,
};
pub use crate::graph::{EncodingVariant, GraphNode, GraphWalk};
pub use crate::kem::{KEM_SHARED_KEY_BYTES, KemCiphertext, decapsulate, encapsulate};
pub use crate::payload::{
    EncryptedPayload, PayloadLayer, PayloadOptions, PayloadView, decrypt_payload,
    decrypt_payload_view, encrypt_payload,
};
pub use crate::polymorph::{PolymorphismEngine, ProfileSelection};
pub use crate::preset::{PolymorphismIntensity, SecurityLevel, SecurityPreset, security_preset};
pub use crate::profiles::{
    Profile, ProfileId, ProfileRegistry, phase1_profiles, profile_phase1, registry_paranoid,
    registry_standard,
};
pub use crate::ring::{RingBackend, RingElement, RingParams};
pub use crate::rng::{SecureRng, derive_session_rng, fill_session_bytes, secure_rng};
pub use crate::scheduler::{ChaoticScheduler, SchedulerParams, SchedulerTrace};
pub use crate::session::{PlumeSession, PlumeSessionError};

/// Stable alias for the polymorphic key bundle.
pub type KeyBundle = PolyKeyPair;
/// Stable alias for the serialized payload format.
pub type PlumePayload = EncryptedPayload;
pub use crate::versioning::*;
