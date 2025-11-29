use crate::{Keypair, Signature};
use base64::{engine::general_purpose, Engine as _};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

/// The Ncryptf JSON content type
pub const NCRYPTF_CONTENT_TYPE: &str = "application/vnd.ncryptf+json";

/// The amount of time (in either direction) a request time may differ by and still be accepted.
pub const NCRYPTF_DRIFT_ALLOWANCE: i32 = 90;

/// Reusable encryption key data for client parsing
///
/// This is exported for use in your application for deserializing the request.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExportableEncryptionKeyData {
    pub public: String,
    pub signature: String,
    pub hash_id: String,
    pub expires_at: i64,
    pub ephemeral: bool,
}

impl ExportableEncryptionKeyData {
    /// Returns true if this key is expired
    pub fn is_expired(&self) -> bool {
        return chrono::Utc::now().timestamp() >= self.expires_at;
    }

    /// Returns the public key as a Vec
    pub fn get_public_key(&self) -> Option<Vec<u8>> {
        if self.public.is_empty() {
            return None;
        }

        return Some(general_purpose::STANDARD.decode(self.public.clone()).unwrap());
    }

    /// Returns the signature key as a Vec
    pub fn get_signature_key(&self) -> Option<Vec<u8>> {
        if self.public.is_empty() {
            return None;
        }

        return Some(general_purpose::STANDARD.decode(self.signature.clone()).unwrap());
    }
}

/// Represents an Encryption key used to encrypt and decrypt requests
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionKey {
    bkp: Keypair,
    skp: Keypair,
    ephemeral: bool,
    pub expires_at: i64,
    hash_id: String,
}

impl EncryptionKey {
    /// Returns the box keypair
    pub fn get_box_kp(&self) -> Keypair {
        return self.bkp.clone();
    }

    /// Returns the signing keypair
    pub fn get_sign_kp(&self) -> Keypair {
        return self.skp.clone();
    }

    /// Returns true if the key is meant to be used only once
    pub fn is_ephemeral(&self) -> bool {
        return self.ephemeral;
    }

    /// Returns the hash id
    pub fn get_hash_id(&self) -> String {
        return self.hash_id.clone();
    }

    /// Returns true if the token is expired
    /// Expiration should be handled server side
    /// But the client should know if they need a new key
    pub fn is_expired(&self) -> bool {
        if chrono::Utc::now().timestamp() >= self.expires_at {
            return true;
        }

        return false;
    }

    /// Creates a new struct with an ephemeral flag set
    pub fn new(ephemeral: bool) -> Self {
        let s: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        // Encryption keys are valid for an hour
        let expiration = chrono::Utc::now() + chrono::Duration::hours(1);
        return Self {
            bkp: Keypair::new(),
            skp: Signature::new(),
            ephemeral: ephemeral,
            expires_at: expiration.timestamp(),
            hash_id: s,
        };
    }
}