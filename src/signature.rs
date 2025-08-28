extern crate base64;
use base64::{engine::general_purpose, Engine as _};
use chrono::{offset::Utc, DateTime};

use dryoc::generichash::GenericHash;
use dryoc::classic::crypto_sign::crypto_sign_keypair;

use crate::Keypair;

/// Represents a signature and provides utility methods for validating signatures on a request.
pub struct Signature;

impl Signature {
    /// Derives a signature from the given parameters
    pub fn derive(
        method: String,
        uri: String,
        salt: Vec<u8>,
        datetime: DateTime<Utc>,
        payload: String,
        version: Option<i8>,
    ) -> String {
        let v = match version {
            Some(v) => Some(v),
            None => Some(crate::NCRYPTF_CURRENT_VERSION),
        };

        let hash = Self::get_signature_hash(payload, salt.clone(), v);
        let b64s = general_purpose::STANDARD.encode(salt);
        let ts = datetime.format("%a, %d %b %Y %H:%M:%S %z").to_string();

        return format!("{}\n{}+{}\n{}\n{}", hash, method, uri, ts, b64s);
    }

    /// Generates a new random signature
    pub fn new() -> Keypair {
        let (pk, sk) = crypto_sign_keypair();

        return Keypair {
            secret_key: sk.to_vec(),
            public_key: pk.to_vec(),
        };
    }

    /// Generates a signature hash given a salt and data
    pub fn get_signature_hash(data: String, salt: Vec<u8>, version: Option<i8>) -> String {
        match version {
            Some(2) => {
                let salt_key: &[u8; 32] = &salt.try_into().unwrap();
                let input = data.as_bytes();
                
                let hash: [u8; 64] = GenericHash::hash(input, Some(salt_key))
                    .expect("Failed to compute generic hash");

                return general_purpose::STANDARD.encode(&hash);
            }
            _ => {
                return sha256::digest(data);
            }
        }
    }
}
