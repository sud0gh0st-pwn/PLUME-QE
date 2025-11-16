use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json;

use crate::context::{ContextFingerprint, mix_seed_with_fingerprint};
use crate::crypto::{PlumeError, PolyPublicKey, PolySecretKey};
use crate::payload::{
    EncryptedPayload, PayloadOptions, PayloadView, decrypt_payload, decrypt_payload_view,
    encrypt_payload,
};
use crate::polymorph::PolymorphismEngine;
use crate::preset::{PolymorphismIntensity, SecurityLevel, SecurityPreset, security_preset};
use crate::scheduler::{ChaoticScheduler, SchedulerParams};

const FILE_PAYLOAD_VERSION: u16 = 1;
const FILE_CHUNK_BYTES: usize = 1 << 20;

#[derive(Debug, Serialize, Deserialize)]
struct FileChunkHeader {
    version: u16,
    chunk_size: usize,
    total_len: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileChunkRecord {
    index: u64,
    len: u64,
    payload: EncryptedPayload,
}

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

/// Stable high-level session for GUI/server integration.
pub struct PlumeSession {
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: ContextFingerprint,
}

impl PlumeSession {
    /// Creates a session configured for the given security level, intensity, and context fingerprint.
    pub fn new(
        level: SecurityLevel,
        intensity: PolymorphismIntensity,
        fingerprint: impl Into<ContextFingerprint>,
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

    /// Encrypts an in-memory byte slice using the session defaults.
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
            self.fingerprint.as_bytes(),
        )
        .map_err(Into::into)
    }

    /// Decrypts a payload produced by `encrypt_bytes`.
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
            self.fingerprint.as_bytes(),
        )
        .map_err(Into::into)
    }

    /// Encrypts a file and writes a JSON payload to `output`.
    pub fn encrypt_file(
        &self,
        keys: &PolyPublicKey,
        seed: &[u8],
        message_index: u64,
        input: &Path,
        output: &Path,
    ) -> Result<(), PlumeSessionError> {
        let mut reader = BufReader::new(File::open(input)?);
        let seed_bytes = self.session_seed(seed);
        let engine = self.engine();
        let total_len = fs::metadata(input)?.len();
        let mut writer = BufWriter::new(File::create(output)?);
        let header = FileChunkHeader {
            version: FILE_PAYLOAD_VERSION,
            chunk_size: FILE_CHUNK_BYTES,
            total_len,
        };
        serde_json::to_writer(&mut writer, &header)?;
        writer.write_all(b"\n")?;
        let mut buffer = vec![0u8; FILE_CHUNK_BYTES];
        let mut chunk_index = 0u64;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let chunk_slice = &buffer[..read];
            let options = if self.preset.default_multiview {
                PayloadOptions {
                    cover_plaintext: b"PLUME-QE COVER",
                    cover_aad: b"",
                    inner_plaintext: Some(chunk_slice),
                    inner_aad: Some(b""),
                }
            } else {
                PayloadOptions::cover_only(chunk_slice, b"")
            };
            let payload = encrypt_payload(
                &engine,
                keys,
                &seed_bytes,
                message_index + chunk_index,
                options,
                self.fingerprint.as_bytes(),
            )?;
            let record = FileChunkRecord {
                index: chunk_index,
                len: read as u64,
                payload,
            };
            serde_json::to_writer(&mut writer, &record)?;
            writer.write_all(b"\n")?;
            chunk_index += 1;
        }
        writer.flush()?;
        Ok(())
    }

    /// Decrypts a payload file written by `encrypt_file`.
    pub fn decrypt_file(
        &self,
        keys: &PolySecretKey,
        seed: &[u8],
        message_index: u64,
        input: &Path,
        output: &Path,
    ) -> Result<(), PlumeSessionError> {
        let engine = self.engine();
        let seed_bytes = self.session_seed(seed);
        if self.try_decrypt_chunked(&engine, keys, &seed_bytes, message_index, input, output)? {
            return Ok(());
        }
        let reader = BufReader::new(File::open(input)?);
        let payload: EncryptedPayload = serde_json::from_reader(reader)?;
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
            self.fingerprint.as_bytes(),
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
        mix_seed_with_fingerprint(seed, self.fingerprint.as_bytes())
    }

    fn try_decrypt_chunked(
        &self,
        engine: &PolymorphismEngine<'static>,
        keys: &PolySecretKey,
        seed_bytes: &[u8],
        message_index: u64,
        input: &Path,
        output: &Path,
    ) -> Result<bool, PlumeSessionError> {
        let file = File::open(input)?;
        let mut reader = BufReader::new(file);
        let mut header_line = String::new();
        if reader.read_line(&mut header_line)? == 0 {
            return Ok(false);
        }
        let trimmed = header_line.trim();
        if trimmed.is_empty() {
            return Ok(false);
        }
        let header = match serde_json::from_str::<FileChunkHeader>(trimmed) {
            Ok(header) => header,
            Err(_) => return Ok(false),
        };
        if header.version != FILE_PAYLOAD_VERSION {
            return Err(PlumeSessionError::Crypto(PlumeError::VersionMismatch {
                context: "ChunkedFilePayload",
                expected: FILE_PAYLOAD_VERSION,
                found: header.version,
            }));
        }
        let mut writer = BufWriter::new(File::create(output)?);
        let view = if self.preset.default_inner_view {
            PayloadView::Inner
        } else {
            PayloadView::Cover
        };
        let mut line = String::new();
        while reader.read_line(&mut line)? != 0 {
            if line.trim().is_empty() {
                line.clear();
                continue;
            }
            let record: FileChunkRecord = serde_json::from_str(line.trim())?;
            let chunk_plain = decrypt_payload_view(
                engine,
                keys,
                seed_bytes,
                message_index + record.index,
                &record.payload,
                self.fingerprint.as_bytes(),
                view,
            )?;
            writer.write_all(&chunk_plain)?;
            line.clear();
        }
        writer.flush()?;
        Ok(true)
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

    #[test]
    fn session_decrypt_legacy_file() {
        let mut rng = secure_rng();
        let bundle = keygen_bundle_with_rng(ProfileRegistry::phase1(), &mut rng);
        let session = PlumeSession::new(SecurityLevel::Toy, PolymorphismIntensity::Low, b"ctx");
        let engine = session.engine();
        let seed_bytes = session.session_seed(b"legacy");
        let payload = encrypt_payload(
            &engine,
            &bundle.public,
            &seed_bytes,
            0,
            PayloadOptions::cover_only(b"legacy-bytes", b""),
            session.fingerprint.as_bytes(),
        )
        .unwrap();
        let payload_path = NamedTempFile::new().unwrap();
        let writer = BufWriter::new(File::create(payload_path.path()).unwrap());
        serde_json::to_writer_pretty(writer, &payload).unwrap();
        let output = NamedTempFile::new().unwrap();
        session
            .decrypt_file(
                &bundle.secret,
                b"legacy",
                0,
                payload_path.path(),
                output.path(),
            )
            .unwrap();
        let recovered = fs::read(output.path()).unwrap();
        assert_eq!(recovered, b"legacy-bytes");
    }

    #[test]
    fn session_standard_bytes_roundtrip() {
        let mut rng = secure_rng();
        let bundle = keygen_bundle_with_rng(ProfileRegistry::standard(), &mut rng);
        let session = PlumeSession::new(
            SecurityLevel::Standard,
            PolymorphismIntensity::Medium,
            b"ctx",
        );
        let payload = session
            .encrypt_bytes(&bundle.public, b"std-seed", 0, b"standard", b"aad")
            .unwrap();
        let recovered = session
            .decrypt_bytes(&bundle.secret, b"std-seed", 0, &payload)
            .unwrap();
        assert_eq!(recovered, b"standard");
    }
}
