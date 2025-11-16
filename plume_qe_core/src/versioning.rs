//! Serialization versioning helpers.

use serde::de::Error as DeError;

pub const POLY_PUBLIC_KEY_VERSION: u16 = 1;
pub const POLY_SECRET_KEY_VERSION: u16 = 1;
pub const POLY_KEYPAIR_VERSION: u16 = 1;
pub const CIPHERTEXT_VERSION: u16 = 1;
pub const KEM_CIPHERTEXT_VERSION: u16 = 1;
pub const ENCRYPTED_PAYLOAD_VERSION: u16 = 1;

pub fn expect_version<E: DeError>(found: u16, expected: u16, label: &'static str) -> Result<(), E> {
    if found != expected {
        return Err(E::custom(format!(
            "{} version mismatch: expected {}, found {}",
            label, expected, found
        )));
    }
    Ok(())
}
