use blake3::Hasher;
use log::debug;
use rand_core::{CryptoRng, RngCore};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use thiserror::Error;

use crate::polymorph::PolymorphismEngine;
use crate::profiles::{Profile, ProfileId, ProfileRegistry};
use crate::ring::{RingElement, RingParams};
use crate::rng::secure_rng;
use crate::versioning::{
    CIPHERTEXT_VERSION, POLY_KEYPAIR_VERSION, POLY_PUBLIC_KEY_VERSION, POLY_SECRET_KEY_VERSION,
    expect_version,
};

const INTEGRITY_TAG_BYTES: usize = 16;
const CONTEXT_GUARD_BYTES: usize = 32;
const DIRECT_CONTEXT_LABEL: &[u8] = b"plume-qe::direct";

#[derive(Debug, Error)]
pub enum PlumeError {
    #[error("profile mismatch: expected {expected:?}, found {found:?}")]
    ProfileMismatch {
        expected: ProfileId,
        found: ProfileId,
    },

    #[error("ciphertext profile {ciphertext:?} does not match key profile {key:?}")]
    CiphertextProfileMismatch {
        ciphertext: ProfileId,
        key: ProfileId,
    },

    #[error("missing {kind} key for profile {profile:?}")]
    MissingProfileKey {
        kind: &'static str,
        profile: ProfileId,
    },

    #[error("serialization version mismatch for {context}: expected {expected}, found {found}")]
    VersionMismatch {
        context: &'static str,
        expected: u16,
        found: u16,
    },

    #[error("ciphertext integrity check failed")]
    IntegrityCheckFailed,

    #[error("context guard mismatch")]
    ContextGuardMismatch,

    #[error("scheduler mismatch between ciphertext and selection")]
    SchedulerMismatch,

    #[error("payload does not contain the requested inner view")]
    MissingInnerView,

    #[error("AEAD operation failed")]
    AeadError,

    #[error("context fingerprint mismatch")]
    FingerprintMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub profile: ProfileId,
    pub a: RingElement,
    pub b: RingElement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKey {
    pub profile: ProfileId,
    pub s: RingElement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyPublicKey {
    pub version: u16,
    pub keys: HashMap<ProfileId, PublicKey>,
}

impl PolyPublicKey {
    pub fn get(&self, id: ProfileId) -> Option<&PublicKey> {
        self.keys.get(&id)
    }

    pub fn profiles(&self) -> impl Iterator<Item = ProfileId> + '_ {
        self.keys.keys().copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolySecretKey {
    pub version: u16,
    pub keys: HashMap<ProfileId, SecretKey>,
}

impl PolySecretKey {
    pub fn get(&self, id: ProfileId) -> Option<&SecretKey> {
        self.keys.get(&id)
    }
}

impl Serialize for PolyPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PolyPublicKey", 2)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("keys", &self.keys)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PolyPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: u16,
            keys: HashMap<ProfileId, PublicKey>,
        }
        let helper = Helper::deserialize(deserializer)?;
        expect_version::<D::Error>(helper.version, POLY_PUBLIC_KEY_VERSION, "PolyPublicKey")?;
        Ok(Self {
            version: helper.version,
            keys: helper.keys,
        })
    }
}

impl Serialize for PolySecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PolySecretKey", 2)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("keys", &self.keys)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PolySecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: u16,
            keys: HashMap<ProfileId, SecretKey>,
        }
        let helper = Helper::deserialize(deserializer)?;
        expect_version::<D::Error>(helper.version, POLY_SECRET_KEY_VERSION, "PolySecretKey")?;
        Ok(Self {
            version: helper.version,
            keys: helper.keys,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyKeyPair {
    pub version: u16,
    pub public: PolyPublicKey,
    pub secret: PolySecretKey,
}

impl Serialize for PolyKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PolyKeyPair", 3)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("public", &self.public)?;
        state.serialize_field("secret", &self.secret)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PolyKeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: u16,
            public: PolyPublicKey,
            secret: PolySecretKey,
        }
        let helper = Helper::deserialize(deserializer)?;
        expect_version::<D::Error>(helper.version, POLY_KEYPAIR_VERSION, "PolyKeyPair")?;
        Ok(Self {
            version: helper.version,
            public: helper.public,
            secret: helper.secret,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextBlock {
    pub c1: RingElement,
    pub c2: RingElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub version: u16,
    pub profile: ProfileId,
    pub blocks: Vec<CiphertextBlock>,
    pub plaintext_len: usize,
    pub integrity_tag: [u8; INTEGRITY_TAG_BYTES],
    pub context_guard: [u8; CONTEXT_GUARD_BYTES],
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Ciphertext", 6)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("profile", &self.profile)?;
        state.serialize_field("blocks", &self.blocks)?;
        state.serialize_field("plaintext_len", &self.plaintext_len)?;
        state.serialize_field("integrity_tag", &self.integrity_tag)?;
        state.serialize_field("context_guard", &self.context_guard)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: u16,
            profile: ProfileId,
            blocks: Vec<CiphertextBlock>,
            plaintext_len: usize,
            integrity_tag: [u8; INTEGRITY_TAG_BYTES],
            context_guard: [u8; CONTEXT_GUARD_BYTES],
        }
        let helper = Helper::deserialize(deserializer)?;
        expect_version::<D::Error>(helper.version, CIPHERTEXT_VERSION, "Ciphertext")?;
        Ok(Self {
            version: helper.version,
            profile: helper.profile,
            blocks: helper.blocks,
            plaintext_len: helper.plaintext_len,
            integrity_tag: helper.integrity_tag,
            context_guard: helper.context_guard,
        })
    }
}

pub fn keygen(profile: &Profile) -> KeyPair {
    let mut rng = secure_rng();
    keygen_with_rng(profile, &mut rng)
}

pub fn keygen_with_rng<R: CryptoRng + RngCore>(profile: &Profile, rng: &mut R) -> KeyPair {
    let params = profile.ring;
    let a = RingElement::random_uniform(params, rng);
    let s = RingElement::sample_noise(params, profile.noise_width, rng);
    let e = RingElement::sample_noise(params, profile.noise_width, rng);
    let b = a.mul(&s).add(&e);
    KeyPair {
        public: PublicKey {
            profile: profile.id,
            a,
            b,
        },
        secret: SecretKey {
            profile: profile.id,
            s,
        },
    }
}

pub fn keygen_bundle(registry: ProfileRegistry<'_>) -> PolyKeyPair {
    let mut rng = secure_rng();
    keygen_bundle_with_rng(registry, &mut rng)
}

pub fn keygen_bundle_with_rng<R: CryptoRng + RngCore>(
    registry: ProfileRegistry<'_>,
    rng: &mut R,
) -> PolyKeyPair {
    let mut public = HashMap::new();
    let mut secret = HashMap::new();

    for profile in registry.profiles() {
        let pair = keygen_with_rng(profile, rng);
        public.insert(profile.id, pair.public);
        secret.insert(profile.id, pair.secret);
    }

    PolyKeyPair {
        version: POLY_KEYPAIR_VERSION,
        public: PolyPublicKey {
            version: POLY_PUBLIC_KEY_VERSION,
            keys: public,
        },
        secret: PolySecretKey {
            version: POLY_SECRET_KEY_VERSION,
            keys: secret,
        },
    }
}

pub fn encrypt_with_profile<R: CryptoRng + RngCore>(
    profile: &Profile,
    pk: &PublicKey,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Ciphertext, PlumeError> {
    let guard = direct_context_guard();
    encrypt_with_profile_guard(profile, pk, plaintext, &guard, rng)
}

pub(crate) fn encrypt_with_profile_guard<R: CryptoRng + RngCore>(
    profile: &Profile,
    pk: &PublicKey,
    plaintext: &[u8],
    context_guard: &[u8; CONTEXT_GUARD_BYTES],
    rng: &mut R,
) -> Result<Ciphertext, PlumeError> {
    if pk.profile != profile.id {
        return Err(PlumeError::ProfileMismatch {
            expected: profile.id,
            found: pk.profile,
        });
    }

    let params = profile.ring;
    let block_size = params.degree;
    let mut blocks = Vec::with_capacity((plaintext.len() + block_size - 1) / block_size);

    for chunk in plaintext.chunks(block_size) {
        let message = encode_block(params, chunk);
        let u = RingElement::sample_noise(params, profile.noise_width, rng);
        let e1 = RingElement::sample_noise(params, profile.noise_width, rng);
        let e2 = RingElement::sample_noise(params, profile.noise_width, rng);
        let c1 = pk.a.mul(&u).add(&e1);
        let c2 = pk.b.mul(&u).add(&e2).add(&message);
        blocks.push(CiphertextBlock { c1, c2 });
    }

    Ok(Ciphertext {
        version: CIPHERTEXT_VERSION,
        profile: profile.id,
        blocks,
        plaintext_len: plaintext.len(),
        integrity_tag: compute_integrity_tag(profile.id, plaintext),
        context_guard: *context_guard,
    })
}

pub fn decrypt_with_profile(
    profile: &Profile,
    sk: &SecretKey,
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>, PlumeError> {
    let guard = direct_context_guard();
    decrypt_with_profile_guard(profile, sk, ciphertext, &guard)
}

pub(crate) fn decrypt_with_profile_guard(
    profile: &Profile,
    sk: &SecretKey,
    ciphertext: &Ciphertext,
    expected_guard: &[u8; CONTEXT_GUARD_BYTES],
) -> Result<Vec<u8>, PlumeError> {
    if sk.profile != profile.id {
        return Err(PlumeError::ProfileMismatch {
            expected: profile.id,
            found: sk.profile,
        });
    }
    if ciphertext.profile != profile.id {
        return Err(PlumeError::CiphertextProfileMismatch {
            ciphertext: ciphertext.profile,
            key: profile.id,
        });
    }
    if ciphertext.version != CIPHERTEXT_VERSION {
        return Err(PlumeError::VersionMismatch {
            context: "Ciphertext",
            expected: CIPHERTEXT_VERSION,
            found: ciphertext.version,
        });
    }
    if ciphertext.context_guard != *expected_guard {
        return Err(PlumeError::ContextGuardMismatch);
    }

    let params = profile.ring;
    let block_size = params.degree;
    let mut plaintext = Vec::with_capacity(ciphertext.plaintext_len);

    for (block_index, block) in ciphertext.blocks.iter().enumerate() {
        let expected_len = block_length(ciphertext.plaintext_len, block_size, block_index);
        let decoded_ring = block.c2.sub(&block.c1.mul(&sk.s));
        let mut decoded = decode_block(params, &decoded_ring, expected_len);
        plaintext.append(&mut decoded);
    }

    plaintext.truncate(ciphertext.plaintext_len);
    let expected_tag = compute_integrity_tag(profile.id, &plaintext);
    if ciphertext.integrity_tag != expected_tag {
        return Err(PlumeError::IntegrityCheckFailed);
    }
    Ok(plaintext)
}

pub fn encrypt<R: CryptoRng + RngCore>(
    engine: &PolymorphismEngine,
    keys: &PolyPublicKey,
    seed: &[u8],
    message_index: u64,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Ciphertext, PlumeError> {
    let selection = engine.select_profile_with_trace(seed, message_index);
    let pk = keys
        .get(selection.profile.id)
        .ok_or(PlumeError::MissingProfileKey {
            kind: "public",
            profile: selection.profile.id,
        })?;
    let context_guard = context_guard_from_seed(seed, message_index);
    let ciphertext =
        encrypt_with_profile_guard(selection.profile, pk, plaintext, &context_guard, rng)?;
    debug!(
        "encrypt msg_index={} profile={:?} degree={} blocks={}",
        message_index,
        selection.profile.id,
        selection.profile.ring.degree,
        ciphertext.blocks.len()
    );
    Ok(ciphertext)
}

pub fn decrypt(
    engine: &PolymorphismEngine,
    keys: &PolySecretKey,
    seed: &[u8],
    message_index: u64,
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>, PlumeError> {
    let selection = engine.select_profile_with_trace(seed, message_index);
    let sk = keys
        .get(selection.profile.id)
        .ok_or(PlumeError::MissingProfileKey {
            kind: "secret",
            profile: selection.profile.id,
        })?;
    let context_guard = context_guard_from_seed(seed, message_index);
    let plaintext = decrypt_with_profile_guard(selection.profile, sk, ciphertext, &context_guard)?;
    debug!(
        "decrypt msg_index={} profile={:?} plaintext_len={}",
        message_index,
        selection.profile.id,
        plaintext.len()
    );
    Ok(plaintext)
}

fn block_length(total_len: usize, block_size: usize, block_index: usize) -> usize {
    let consumed = block_index * block_size;
    if consumed >= total_len {
        0
    } else {
        (total_len - consumed).min(block_size)
    }
}

fn encode_block(params: RingParams, chunk: &[u8]) -> RingElement {
    let mut coeffs = vec![0i64; params.degree];
    let scale = params.scaling_factor();
    for (i, &byte) in chunk.iter().enumerate() {
        coeffs[i] = (byte as i64) * scale;
    }
    RingElement::from_coeffs(params, coeffs)
}

fn decode_block(params: RingParams, element: &RingElement, length: usize) -> Vec<u8> {
    let scale = params.scaling_factor();
    let mut output = Vec::with_capacity(length);
    for coeff in element.coeffs().iter().take(length) {
        let centered = params.center(*coeff);
        let value = ((centered + scale / 2) / scale).clamp(0, params.plaintext_modulus - 1) as u8;
        output.push(value);
    }
    output
}

fn compute_integrity_tag(profile: ProfileId, plaintext: &[u8]) -> [u8; INTEGRITY_TAG_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::integrity");
    hasher.update(&profile.0.to_le_bytes());
    hasher.update(plaintext);
    let digest = hasher.finalize();
    let mut tag = [0u8; INTEGRITY_TAG_BYTES];
    tag.copy_from_slice(&digest.as_bytes()[..INTEGRITY_TAG_BYTES]);
    tag
}

pub(crate) fn context_guard_from_seed(
    seed: &[u8],
    message_index: u64,
) -> [u8; CONTEXT_GUARD_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::context");
    hasher.update(seed);
    hasher.update(&message_index.to_le_bytes());
    finalize_guard(hasher)
}

fn direct_context_guard() -> [u8; CONTEXT_GUARD_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(DIRECT_CONTEXT_LABEL);
    finalize_guard(hasher)
}

fn finalize_guard(hasher: Hasher) -> [u8; CONTEXT_GUARD_BYTES] {
    let digest = hasher.finalize();
    let mut guard = [0u8; CONTEXT_GUARD_BYTES];
    guard.copy_from_slice(&digest.as_bytes()[..CONTEXT_GUARD_BYTES]);
    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polymorph::PolymorphismEngine;
    use crate::profiles::{phase1_profiles, profile_phase1};
    use crate::rng::derive_session_rng;
    use proptest::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn per_profile_roundtrip() {
        for profile in phase1_profiles() {
            let mut rng = secure_rng();
            let pair = keygen_with_rng(profile, &mut rng);
            let messages = [
                b"tiny".to_vec(),
                vec![0x42; profile.ring.degree + 3],
                (0u8..64).collect::<Vec<_>>(),
            ];
            for msg in messages {
                let mut enc_rng = secure_rng();
                let ct = encrypt_with_profile(profile, &pair.public, &msg, &mut enc_rng).unwrap();
                let recovered = decrypt_with_profile(profile, &pair.secret, &ct).unwrap();
                assert_eq!(msg, recovered);
            }
        }
    }

    #[test]
    fn polymorphic_api_roundtrip_many_seeds() {
        let engine = PolymorphismEngine::phase1();
        let mut key_rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut key_rng);
        let mut rng = secure_rng();
        for seed_idx in 0..8u8 {
            let seed = format!("phase4-seed-{seed_idx}");
            for msg_index in 0..12u64 {
                let payload = format!("payload-{seed_idx}-{msg_index}");
                let ciphertext = encrypt(
                    &engine,
                    &pair.public,
                    seed.as_bytes(),
                    msg_index,
                    payload.as_bytes(),
                    &mut rng,
                )
                .unwrap();
                let recovered = decrypt(
                    &engine,
                    &pair.secret,
                    seed.as_bytes(),
                    msg_index,
                    &ciphertext,
                )
                .unwrap();
                assert_eq!(recovered, payload.as_bytes());
            }
        }
    }

    #[test]
    fn polymorphism_switches_profiles() {
        let engine = PolymorphismEngine::phase1();
        let mut key_rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut key_rng);
        let mut rng = secure_rng();

        let seed = b"phase1-switch-seed";
        let mut seen = HashSet::new();
        for msg_index in 0..12u64 {
            let selection = engine.select_profile_with_trace(seed, msg_index);
            seen.insert(selection.profile.id);
            let payload = format!("message-{msg_index} via {}", selection.profile.name);
            let ciphertext = encrypt(
                &engine,
                &pair.public,
                seed,
                msg_index,
                payload.as_bytes(),
                &mut rng,
            )
            .unwrap();
            let recovered = decrypt(&engine, &pair.secret, seed, msg_index, &ciphertext).unwrap();
            assert_eq!(recovered, payload.as_bytes());
        }

        assert!(
            seen.len() >= 2,
            "expected polymorphism to exercise multiple profiles"
        );
    }

    #[test]
    fn key_bundle_serialization_roundtrip() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let encoded = serde_json::to_vec(&pair).unwrap();
        let decoded: PolyKeyPair = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(pair, decoded);
    }

    #[test]
    fn wrong_seed_rejected() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let mut enc_rng = secure_rng();
        let ciphertext = encrypt(
            &engine,
            &pair.public,
            b"seed-a",
            2,
            b"guard test",
            &mut enc_rng,
        )
        .unwrap();
        let err = decrypt(&engine, &pair.secret, b"seed-b", 2, &ciphertext).unwrap_err();
        assert!(
            matches!(
                err,
                PlumeError::ContextGuardMismatch | PlumeError::CiphertextProfileMismatch { .. }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn wrong_message_index_rejected() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let mut enc_rng = secure_rng();
        let ciphertext = encrypt(
            &engine,
            &pair.public,
            b"seed-a",
            3,
            b"index guard",
            &mut enc_rng,
        )
        .unwrap();
        let err = decrypt(&engine, &pair.secret, b"seed-a", 7, &ciphertext).unwrap_err();
        assert!(matches!(err, PlumeError::ContextGuardMismatch));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let mut enc_rng = secure_rng();
        let ciphertext =
            encrypt(&engine, &pair.public, b"seed-a", 0, b"tamper", &mut enc_rng).unwrap();
        let mut tampered = ciphertext.clone();
        tampered.integrity_tag[0] ^= 0xAA;
        let err = decrypt(&engine, &pair.secret, b"seed-a", 0, &tampered).unwrap_err();
        assert!(matches!(err, PlumeError::IntegrityCheckFailed));
    }

    #[test]
    fn deterministic_rng_roundtrip() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let seed = b"deterministic-seed";
        let mut noise_rng = derive_session_rng(seed, 0, b"deterministic-noise");
        let ciphertext = encrypt(
            &engine,
            &pair.public,
            seed,
            0,
            b"deterministic",
            &mut noise_rng,
        )
        .unwrap();
        let recovered = decrypt(&engine, &pair.secret, seed, 0, &ciphertext).unwrap();
        assert_eq!(b"deterministic".to_vec(), recovered);
    }

    proptest! {
        #[test]
        fn fuzz_decrypt_random_ciphertexts(
            coeffs1 in prop::collection::vec(-5000i64..=5000, 16),
            coeffs2 in prop::collection::vec(-5000i64..=5000, 16),
            len in 0usize..=16
        ) {
            let profile = profile_phase1();
            let params = profile.ring;
            let c1 = RingElement::from_coeffs(params, coeffs1);
            let c2 = RingElement::from_coeffs(params, coeffs2);
            let ciphertext = Ciphertext {
                version: CIPHERTEXT_VERSION,
                profile: profile.id,
                blocks: vec![CiphertextBlock { c1, c2 }],
                plaintext_len: len,
                integrity_tag: [0u8; INTEGRITY_TAG_BYTES],
                context_guard: direct_context_guard(),
            };
            let mut rng = secure_rng();
            let pair = keygen_with_rng(&profile, &mut rng);
            let _ = decrypt_with_profile(&profile, &pair.secret, &ciphertext);
        }
    }
}
