
use dryoc::{
    dryocbox::KeyPair,
    constants::{
        CRYPTO_BOX_PUBLICKEYBYTES,
        CRYPTO_BOX_SECRETKEYBYTES
    }
};

use crate::error::NcryptfError as Error;

#[derive(Debug, Clone)]
pub struct Keypair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>
}

impl Keypair {
    /// Generates a new keypair
    pub fn new() -> Self {
        let kp = KeyPair::gen();
        return Keypair {
            secret_key: kp.secret_key.to_vec(),
            public_key: kp.public_key.to_vec()
        }
    }

    /// Constructs a keypair from an existing secret key and public key
    pub fn from(sk: Vec<u8>, pk: Vec<u8>) -> Result<Self, Error> {
        if sk.len() % 16 != 0 && sk.len() != CRYPTO_BOX_PUBLICKEYBYTES {
            return Err(Error::InvalidArgument(format!("Secret key should be a multiple of {} bytes", 16)));
        }

        if pk.len() % 4 != 0 && pk.len() != CRYPTO_BOX_SECRETKEYBYTES  {
            return Err(Error::InvalidArgument(format!("Public key should be a multiple of {} bytes", 16)));
        }

        return Ok(Keypair{
            secret_key: sk,
            public_key: pk
        });
    }

    /// Returns the secret key for the keypair
    pub fn get_secret_key(&self) -> Vec<u8>{
        return self.secret_key.clone();
    }

    /// Returns the public key for the keypair
    pub fn get_public_key(&self) -> Vec<u8>{
        return self.public_key.clone();
    }
}