use serde::{Deserialize, Serialize};
use crate::Keypair;
use crate::Signature;
use rand::{distributions::Alphanumeric, Rng};

/// Represents an Encryption key used to encrypt and decrypt requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKey {
    bkp: Keypair,
    skp: Keypair,
    ephemeral: bool,
    expires_at: i64,
    hash_id: String
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

    /// Creates a new struct with an ephemeral flag set
    pub fn new(ephemeral: bool) -> Self {
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        return Self {
            bkp: Keypair::new(),
            skp: Signature::new(),
            ephemeral: ephemeral,
            expires_at: chrono::Utc::now().timestamp(),
            hash_id: s
        }
    }
}