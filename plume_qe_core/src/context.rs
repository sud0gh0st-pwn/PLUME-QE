use blake3::Hasher;
use zeroize::Zeroize;

/// Stable wrapper for context fingerprint material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextFingerprint {
    bytes: Vec<u8>,
}

impl ContextFingerprint {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn from_str(text: &str) -> Self {
        Self {
            bytes: text.as_bytes().to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for ContextFingerprint {
    fn from(value: Vec<u8>) -> Self {
        Self::from_bytes(value)
    }
}

impl From<&[u8]> for ContextFingerprint {
    fn from(value: &[u8]) -> Self {
        Self::from_bytes(value.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for ContextFingerprint {
    fn from(value: &[u8; N]) -> Self {
        Self::from_bytes(value.to_vec())
    }
}

impl From<&str> for ContextFingerprint {
    fn from(value: &str) -> Self {
        Self::from_str(value)
    }
}

impl Drop for ContextFingerprint {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub fn mix_seed_with_fingerprint(seed: &[u8], fingerprint: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::seed-mix");
    hasher.update(seed);
    hasher.update(fingerprint);
    hasher.finalize().as_bytes().to_vec()
}

pub fn fingerprint_tag(fingerprint: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::fingerprint");
    hasher.update(fingerprint);
    let digest = hasher.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&digest.as_bytes()[..32]);
    tag
}
