use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::aead::{AEAD_NONCE_BYTES, decrypt_aead, encrypt_aead};
use crate::context::fingerprint_tag;
use crate::crypto::{PlumeError, PolyPublicKey, PolySecretKey};
use crate::kem::{KEM_SHARED_KEY_BYTES, KemCiphertext, decapsulate, encapsulate};
use crate::polymorph::PolymorphismEngine;
use crate::versioning::ENCRYPTED_PAYLOAD_VERSION;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadLayer {
    pub nonce: [u8; AEAD_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub version: u16,
    pub kem: KemCiphertext,
    pub cover_layer: PayloadLayer,
    pub inner_layer: Option<PayloadLayer>,
    pub has_inner_view: bool,
    pub fingerprint_tag: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub enum PayloadView {
    Cover,
    Inner,
}

#[derive(Clone, Debug)]
pub struct PayloadOptions<'a> {
    pub cover_plaintext: &'a [u8],
    pub cover_aad: &'a [u8],
    pub inner_plaintext: Option<&'a [u8]>,
    pub inner_aad: Option<&'a [u8]>,
}

impl<'a> PayloadOptions<'a> {
    pub fn cover_only(plaintext: &'a [u8], aad: &'a [u8]) -> Self {
        Self {
            cover_plaintext: plaintext,
            cover_aad: aad,
            inner_plaintext: None,
            inner_aad: None,
        }
    }
}

pub fn encrypt_payload(
    engine: &PolymorphismEngine,
    keys: &PolyPublicKey,
    seed: &[u8],
    message_index: u64,
    options: PayloadOptions<'_>,
    fingerprint: &[u8],
) -> Result<EncryptedPayload, PlumeError> {
    let (kem, shared) = encapsulate(engine, keys, seed, message_index)?;
    let tag = fingerprint_tag(fingerprint);

    let cover_key = derive_layer_key(&shared, b"cover");
    let cover_nonce = derive_nonce(seed, message_index, &kem, &tag, b"cover");
    let cover_ciphertext = encrypt_aead(
        &cover_key,
        &cover_nonce,
        options.cover_plaintext,
        options.cover_aad,
    )?;
    let cover_layer = PayloadLayer {
        nonce: cover_nonce,
        ciphertext: cover_ciphertext,
        aad: options.cover_aad.to_vec(),
    };

    let (inner_layer, has_inner_view) = if let Some(inner_plain) = options.inner_plaintext {
        let inner_key = derive_layer_key(&shared, b"inner");
        let inner_aad = options.inner_aad.unwrap_or(&[]);
        let inner_nonce = derive_nonce(seed, message_index, &kem, &tag, b"inner");
        let inner_ciphertext = encrypt_aead(&inner_key, &inner_nonce, inner_plain, inner_aad)?;
        (
            Some(PayloadLayer {
                nonce: inner_nonce,
                ciphertext: inner_ciphertext,
                aad: inner_aad.to_vec(),
            }),
            true,
        )
    } else {
        (None, false)
    };

    Ok(EncryptedPayload {
        version: ENCRYPTED_PAYLOAD_VERSION,
        kem,
        cover_layer,
        inner_layer,
        has_inner_view,
        fingerprint_tag: tag,
    })
}

pub fn decrypt_payload(
    engine: &PolymorphismEngine,
    keys: &PolySecretKey,
    seed: &[u8],
    message_index: u64,
    payload: &EncryptedPayload,
    fingerprint: &[u8],
) -> Result<Vec<u8>, PlumeError> {
    decrypt_payload_view(
        engine,
        keys,
        seed,
        message_index,
        payload,
        fingerprint,
        PayloadView::Cover,
    )
}

pub fn decrypt_payload_view(
    engine: &PolymorphismEngine,
    keys: &PolySecretKey,
    seed: &[u8],
    message_index: u64,
    payload: &EncryptedPayload,
    fingerprint: &[u8],
    view: PayloadView,
) -> Result<Vec<u8>, PlumeError> {
    if payload.version != ENCRYPTED_PAYLOAD_VERSION {
        return Err(PlumeError::VersionMismatch {
            context: "EncryptedPayload",
            expected: ENCRYPTED_PAYLOAD_VERSION,
            found: payload.version,
        });
    }
    let tag = fingerprint_tag(fingerprint);
    if payload.fingerprint_tag != tag {
        return Err(PlumeError::FingerprintMismatch);
    }
    let shared = decapsulate(engine, keys, seed, message_index, &payload.kem)?;

    match view {
        PayloadView::Cover => {
            let key = derive_layer_key(&shared, b"cover");
            decrypt_layer(&payload.cover_layer, &key)
        }
        PayloadView::Inner => {
            if !payload.has_inner_view {
                return Err(PlumeError::MissingInnerView);
            }
            let layer = payload
                .inner_layer
                .as_ref()
                .ok_or(PlumeError::MissingInnerView)?;
            let key = derive_layer_key(&shared, b"inner");
            decrypt_layer(layer, &key)
        }
    }
}

fn decrypt_layer(
    layer: &PayloadLayer,
    key: &[u8; KEM_SHARED_KEY_BYTES],
) -> Result<Vec<u8>, PlumeError> {
    decrypt_aead(key, &layer.nonce, &layer.ciphertext, &layer.aad)
}

fn derive_layer_key(
    shared: &[u8; KEM_SHARED_KEY_BYTES],
    label: &[u8],
) -> [u8; KEM_SHARED_KEY_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::payload-key");
    hasher.update(shared);
    hasher.update(label);
    let digest = hasher.finalize();
    let mut key = [0u8; KEM_SHARED_KEY_BYTES];
    key.copy_from_slice(&digest.as_bytes()[..KEM_SHARED_KEY_BYTES]);
    key
}

fn derive_nonce(
    seed: &[u8],
    message_index: u64,
    kem: &KemCiphertext,
    fingerprint_tag: &[u8; 32],
    label: &[u8],
) -> [u8; AEAD_NONCE_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::payload-nonce");
    hasher.update(label);
    hasher.update(seed);
    hasher.update(&message_index.to_le_bytes());
    hasher.update(&kem.submode_bits.to_le_bytes());
    hasher.update(&kem.chaotic_value.to_le_bytes());
    hasher.update(&fingerprint_tag[..]);
    let digest = hasher.finalize();
    let mut nonce = [0u8; AEAD_NONCE_BYTES];
    nonce.copy_from_slice(&digest.as_bytes()[..AEAD_NONCE_BYTES]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen_bundle_with_rng;
    use crate::polymorph::PolymorphismEngine;
    use crate::rng::secure_rng;

    #[test]
    fn cover_only_roundtrip() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let bundle = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let seed = b"payload-test";
        let fingerprint = b"context-A";
        let plaintext = b"file bytes";
        let options = PayloadOptions::cover_only(plaintext, b"aad");
        let payload =
            encrypt_payload(&engine, &bundle.public, seed, 5, options, fingerprint).unwrap();
        let recovered =
            decrypt_payload(&engine, &bundle.secret, seed, 5, &payload, fingerprint).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn dual_layer_roundtrip() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let bundle = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let seed = b"payload-test";
        let fingerprint = b"context-A";
        let cover = b"cover bytes";
        let inner = b"real secret";
        let options = PayloadOptions {
            cover_plaintext: cover,
            cover_aad: b"cover-aad",
            inner_plaintext: Some(inner),
            inner_aad: Some(b"inner-aad"),
        };
        let payload =
            encrypt_payload(&engine, &bundle.public, seed, 2, options, fingerprint).unwrap();
        let cover_out = decrypt_payload(&engine, &bundle.secret, seed, 2, &payload, fingerprint)
            .expect("cover decrypt");
        let inner_out = decrypt_payload_view(
            &engine,
            &bundle.secret,
            seed,
            2,
            &payload,
            fingerprint,
            PayloadView::Inner,
        )
        .expect("inner decrypt");
        assert_eq!(cover_out, cover);
        assert_eq!(inner_out, inner);
    }

    #[test]
    fn missing_inner_errors() {
        let engine = PolymorphismEngine::phase1();
        let mut rng = secure_rng();
        let bundle = keygen_bundle_with_rng(engine.registry(), &mut rng);
        let seed = b"payload-test";
        let fingerprint = b"context-A";
        let payload = encrypt_payload(
            &engine,
            &bundle.public,
            seed,
            1,
            PayloadOptions::cover_only(b"cover", b"aad"),
            fingerprint,
        )
        .unwrap();
        let err = decrypt_payload_view(
            &engine,
            &bundle.secret,
            seed,
            1,
            &payload,
            fingerprint,
            PayloadView::Inner,
        )
        .unwrap_err();
        assert!(matches!(err, PlumeError::MissingInnerView));
    }
}
