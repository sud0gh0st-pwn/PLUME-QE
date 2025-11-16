use std::fs;
use std::path::Path;

use serde_json;

use crate::context::mix_seed_with_fingerprint;
use crate::crypto::{PlumeError, PolyPublicKey, PolySecretKey};
use crate::payload::{
    EncryptedPayload, PayloadOptions, PayloadView, decrypt_payload, decrypt_payload_view,
    encrypt_payload,
};
use crate::polymorph::PolymorphismEngine;
use crate::preset::{PolymorphismIntensity, SecurityLevel, SecurityPreset, security_preset};
use crate::scheduler::{ChaoticScheduler, SchedulerParams};

#[derive(Debug)]
pub enum PlumeSessionError {
    Crypto(PlumeError),
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl From<PlumeError> for PlumeSessionError {
    fn from(value: PlumeError) -> Self {
        Self::Crypto(value)
    }
}

impl From<std::io::Error> for PlumeSessionError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PlumeSessionError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}

pub struct PlumeSession {
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: Vec<u8>,
}

impl PlumeSession {
    pub fn new(
        level: SecurityLevel,
        intensity: PolymorphismIntensity,
        fingerprint: impl Into<Vec<u8>>,
    ) -> Self {
        let preset = security_preset(level);
        Self {
            scheduler: preset.scheduler,
            preset,
            intensity,
            fingerprint: fingerprint.into(),
        }
    }

    pub fn with_scheduler(mut self, params: SchedulerParams) -> Self {
        self.scheduler = params;
        self
    }

    pub fn encrypt_bytes(
        &self,
        keys: &PolyPublicKey,
        seed: &[u8],
        message_index: u64,
        data: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedPayload, PlumeSessionError> {
        let options = PayloadOptions::cover_only(data, aad);
        let engine = self.engine();
        let seed_bytes = self.session_seed(seed);
        encrypt_payload(
            &engine,
            keys,
            &seed_bytes,
            message_index,
            options,
            &self.fingerprint,
        )
        .map_err(Into::into)
    }

    pub fn decrypt_bytes(
        &self,
        keys: &PolySecretKey,
        seed: &[u8],
        message_index: u64,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, PlumeSessionError> {
        let engine = self.engine();
        let seed_bytes = self.session_seed(seed);
        decrypt_payload(
            &engine,
            keys,
            &seed_bytes,
            message_index,
            payload,
            &self.fingerprint,
        )
        .map_err(Into::into)
    }

    pub fn encrypt_file(
        &self,
        keys: &PolyPublicKey,
        seed: &[u8],
        message_index: u64,
        input: &Path,
        output: &Path,
    ) -> Result<(), PlumeSessionError> {
        let data = fs::read(input)?;
        let seed_bytes = self.session_seed(seed);
        let engine = self.engine();
        let options = if self.preset.default_multiview {
            PayloadOptions {
                cover_plaintext: b"PLUME-QE COVER",
                cover_aad: b"",
                inner_plaintext: Some(data.as_slice()),
                inner_aad: Some(b""),
            }
        } else {
            PayloadOptions::cover_only(data.as_slice(), b"")
        };
        let payload = encrypt_payload(
            &engine,
            keys,
            &seed_bytes,
            message_index,
            options,
            &self.fingerprint,
        )?;
        let serialized = serde_json::to_string_pretty(&payload)?;
        fs::write(output, serialized)?;
        Ok(())
    }

    pub fn decrypt_file(
        &self,
        keys: &PolySecretKey,
        seed: &[u8],
        message_index: u64,
        input: &Path,
        output: &Path,
    ) -> Result<(), PlumeSessionError> {
        let payload_str = fs::read_to_string(input)?;
        let payload: EncryptedPayload = serde_json::from_str(&payload_str)?;
        let engine = self.engine();
        let seed_bytes = self.session_seed(seed);
        let view = if self.preset.default_inner_view {
            PayloadView::Inner
        } else {
            PayloadView::Cover
        };
        let plaintext = decrypt_payload_view(
            &engine,
            keys,
            &seed_bytes,
            message_index,
            &payload,
            &self.fingerprint,
            view,
        )?;
        fs::write(output, &plaintext)?;
        Ok(())
    }

    fn engine(&self) -> PolymorphismEngine<'static> {
        PolymorphismEngine::new(self.preset.registry)
            .with_scheduler(ChaoticScheduler::new(
                self.scheduler.mu,
                self.scheduler.precision,
            ))
            .with_intensity(self.intensity)
    }

    fn session_seed(&self, seed: &[u8]) -> Vec<u8> {
        mix_seed_with_fingerprint(seed, &self.fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen_bundle_with_rng;
    use crate::profiles::ProfileRegistry;
    use crate::rng::secure_rng;
    use tempfile::NamedTempFile;

    #[test]
    fn session_encrypt_decrypt_bytes() {
        let mut rng = secure_rng();
        let bundle = keygen_bundle_with_rng(ProfileRegistry::phase1(), &mut rng);
        let session = PlumeSession::new(SecurityLevel::Toy, PolymorphismIntensity::Medium, b"ctx");
        let payload = session
            .encrypt_bytes(
                &bundle.public,
                b"session-seed",
                0,
                b"hello",
                b"optional aad",
            )
            .unwrap();
        let recovered = session
            .decrypt_bytes(&bundle.secret, b"session-seed", 0, &payload)
            .unwrap();
        assert_eq!(recovered, b"hello");
    }

    #[test]
    fn session_encrypt_decrypt_file() {
        let mut rng = secure_rng();
        let bundle = keygen_bundle_with_rng(ProfileRegistry::phase1(), &mut rng);
        let session = PlumeSession::new(SecurityLevel::Toy, PolymorphismIntensity::Low, b"ctx");
        let input = NamedTempFile::new().unwrap();
        let output = NamedTempFile::new().unwrap();
        fs::write(input.path(), b"file-data").unwrap();
        let payload_path = NamedTempFile::new().unwrap();
        session
            .encrypt_file(
                &bundle.public,
                b"seed",
                1,
                input.path(),
                payload_path.path(),
            )
            .unwrap();
        session
            .decrypt_file(
                &bundle.secret,
                b"seed",
                1,
                payload_path.path(),
                output.path(),
            )
            .unwrap();
        let recovered = fs::read(output.path()).unwrap();
        assert_eq!(recovered, b"file-data");
    }
}
