use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag, aead::AeadInPlace};

use crate::crypto::PlumeError;

pub const AEAD_NONCE_BYTES: usize = 12;
pub const AEAD_TAG_BYTES: usize = 16;

pub fn encrypt_aead(
    key: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PlumeError> {
    let mut out = Vec::with_capacity(plaintext.len() + AEAD_TAG_BYTES);
    encrypt_aead_into(key, nonce, plaintext, aad, &mut out)?;
    Ok(out)
}

pub fn encrypt_aead_into(
    key: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), PlumeError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    out.clear();
    out.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, out)
        .map_err(|_| PlumeError::AeadError)?;
    out.extend_from_slice(tag.as_slice());
    Ok(())
}

pub fn decrypt_aead(
    key: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PlumeError> {
    let mut out = Vec::with_capacity(ciphertext.len().saturating_sub(AEAD_TAG_BYTES));
    decrypt_aead_into(key, nonce, ciphertext, aad, &mut out)?;
    Ok(out)
}

pub fn decrypt_aead_into(
    key: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), PlumeError> {
    if ciphertext.len() < AEAD_TAG_BYTES {
        return Err(PlumeError::AeadError);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let split = ciphertext.len() - AEAD_TAG_BYTES;
    let (body, tag_bytes) = ciphertext.split_at(split);
    out.clear();
    out.extend_from_slice(body);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            out,
            Tag::from_slice(tag_bytes),
        )
        .map_err(|_| PlumeError::AeadError)
}
