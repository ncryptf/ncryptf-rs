use crate::error::NcryptfError as Error;
use serde::{Deserialize, Serialize};

use dryoc::{constants::{CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES}, dryocbox};

/// Represents a generic keypair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keypair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Keypair {
    /// Generates a new keypair for encryption
    pub fn new() -> Self {
        let mut sk: [u8; CRYPTO_BOX_SECRETKEYBYTES as usize] =
            vec![0; CRYPTO_BOX_SECRETKEYBYTES as usize]
                .try_into()
                .unwrap();
        let mut pk: [u8; CRYPTO_BOX_PUBLICKEYBYTES as usize] =
            vec![0; CRYPTO_BOX_PUBLICKEYBYTES as usize]
                .try_into()
                .unwrap();

        let result = dryocbox::KeyPair::new();
        sk.copy_from_slice(&result.secret_key.as_ref());
        pk.copy_from_slice(&result.public_key.as_ref());
        return Keypair {
            secret_key: sk.to_vec(),
            public_key: pk.to_vec(),
        };
    }

    /// Constructs a keypair from an existing secret key and public key
    pub fn from(sk: Vec<u8>, pk: Vec<u8>) -> Result<Self, Error> {
        if sk.len() % 16 != 0 && sk.len() != (CRYPTO_BOX_PUBLICKEYBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Secret key should be a multiple of {} bytes",
                16
            )));
        }

        if pk.len() % 4 != 0 && pk.len() != (CRYPTO_BOX_SECRETKEYBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Public key should be a multiple of {} bytes",
                16
            )));
        }

        return Ok(Keypair {
            secret_key: sk,
            public_key: pk,
        });
    }

    /// Returns the secret key for the keypair
    pub fn get_secret_key(&self) -> Vec<u8> {
        return self.secret_key.clone();
    }

    /// Returns the public key for the keypair
    pub fn get_public_key(&self) -> Vec<u8> {
        return self.public_key.clone();
    }
}
