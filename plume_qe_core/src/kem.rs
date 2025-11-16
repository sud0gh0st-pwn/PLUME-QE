use blake3::Hasher;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::crypto::{Ciphertext, PlumeError, PolyPublicKey, PolySecretKey, decrypt, encrypt};
use crate::polymorph::{PolymorphismEngine, ProfileSelection};
use crate::rng::{derive_session_rng, fill_session_bytes};
use crate::versioning::{KEM_CIPHERTEXT_VERSION, expect_version};

pub const KEM_SHARED_KEY_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemCiphertext {
    pub version: u16,
    pub ciphertext: Ciphertext,
    pub submode_bits: u8,
    pub chaotic_value: u128,
}

impl Serialize for KemCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("KemCiphertext", 4)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("ciphertext", &self.ciphertext)?;
        state.serialize_field("submode_bits", &self.submode_bits)?;
        state.serialize_field("chaotic_value", &self.chaotic_value)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for KemCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: u16,
            ciphertext: Ciphertext,
            submode_bits: u8,
            chaotic_value: u128,
        }
        let helper = Helper::deserialize(deserializer)?;
        expect_version::<D::Error>(helper.version, KEM_CIPHERTEXT_VERSION, "KemCiphertext")?;
        Ok(Self {
            version: helper.version,
            ciphertext: helper.ciphertext,
            submode_bits: helper.submode_bits,
            chaotic_value: helper.chaotic_value,
        })
    }
}

pub fn encapsulate(
    engine: &PolymorphismEngine,
    keys: &PolyPublicKey,
    seed: &[u8],
    message_index: u64,
) -> Result<(KemCiphertext, [u8; KEM_SHARED_KEY_BYTES]), PlumeError> {
    let selection = engine.select_profile_with_trace(seed, message_index);
    let mut noise_rng = derive_session_rng(seed, message_index, b"plume-kem-noise");
    let mut kem_material = Zeroizing::new([0u8; KEM_SHARED_KEY_BYTES]);
    fill_session_bytes(
        seed,
        message_index,
        b"plume-kem-material",
        kem_material.as_mut(),
    );
    for byte in kem_material.iter_mut() {
        *byte &= 0x3F;
    }
    let ciphertext = encrypt(
        engine,
        keys,
        seed,
        message_index,
        kem_material.as_ref(),
        &mut noise_rng,
    )?;
    let shared_key = derive_shared_key(kem_material.as_ref(), &selection, &ciphertext);
    let kem = KemCiphertext {
        version: KEM_CIPHERTEXT_VERSION,
        ciphertext,
        submode_bits: selection.submode_bits,
        chaotic_value: selection.chaotic_value,
    };
    Ok((kem, shared_key))
}

pub fn decapsulate(
    engine: &PolymorphismEngine,
    keys: &PolySecretKey,
    seed: &[u8],
    message_index: u64,
    kem: &KemCiphertext,
) -> Result<[u8; KEM_SHARED_KEY_BYTES], PlumeError> {
    if kem.version != KEM_CIPHERTEXT_VERSION {
        return Err(PlumeError::VersionMismatch {
            context: "KemCiphertext",
            expected: KEM_CIPHERTEXT_VERSION,
            found: kem.version,
        });
    }
    let selection = engine.select_profile_with_trace(seed, message_index);
    if kem.submode_bits != selection.submode_bits {
        return Err(PlumeError::SchedulerMismatch);
    }
    let kem_material = Zeroizing::new(decrypt(engine, keys, seed, message_index, &kem.ciphertext)?);
    let shared_key = derive_shared_key(kem_material.as_ref(), &selection, &kem.ciphertext);
    Ok(shared_key)
}

fn derive_shared_key(
    kem_material: &[u8],
    selection: &ProfileSelection,
    ciphertext: &Ciphertext,
) -> [u8; KEM_SHARED_KEY_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::kem");
    hasher.update(kem_material);
    hasher.update(&selection.profile.id.0.to_le_bytes());
    hasher.update(&[selection.submode_bits]);
    hasher.update(&selection.chaotic_value.to_le_bytes());
    hasher.update(&ciphertext.context_guard);
    let digest = hasher.finalize();
    let mut shared = [0u8; KEM_SHARED_KEY_BYTES];
    shared.copy_from_slice(&digest.as_bytes()[..KEM_SHARED_KEY_BYTES]);
    shared
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen_bundle_with_rng;
    use crate::rng::secure_rng;

    #[test]
    fn kem_roundtrip() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let seed = b"kem-seed";
        let (kem, shared_enc) = encapsulate(&engine, &pair.public, seed, 0).unwrap();
        let plaintext = decrypt(&engine, &pair.secret, seed, 0, &kem.ciphertext).unwrap();
        assert_eq!(plaintext.len(), KEM_SHARED_KEY_BYTES);
        let shared_dec = decapsulate(&engine, &pair.secret, seed, 0, &kem).unwrap();
        assert_eq!(shared_enc, shared_dec);
    }

    #[test]
    fn kem_wrong_seed_fails() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let pair = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let (kem, shared_enc) = encapsulate(&engine, &pair.public, b"a", 1).unwrap();
        let err = decapsulate(&engine, &pair.secret, b"b", 1, &kem).unwrap_err();
        assert!(matches!(
            err,
            PlumeError::ContextGuardMismatch | PlumeError::SchedulerMismatch
        ));
        assert_eq!(shared_enc.len(), KEM_SHARED_KEY_BYTES);
    }
}
