use dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES;
use libsodium_sys::*;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::NcryptfError as Error;

#[derive(Debug, Clone)]
pub struct Token {
    pub access_token: String,
    pub refresh_token: String,
    pub ikm: Vec<u8>,
    pub signature: Vec<u8>,
    pub expires_at: u64
}

impl Token {
    /// Creates a new token from the provided values
    pub fn from(access_token: String, refresh_token: String, ikm: Vec<u8>, signature: Vec<u8>, expires_at: u64) -> Result<Token, Error> {
        if ikm.len() != 32 {
            return Err(Error::InvalidArgument(format!("Initial key material should be {} bytes", 32)));
        }

        if signature.len() != 64 {
            return Err(Error::InvalidArgument(format!("Signature secret key should be {} bytes", 64)));
        }

        return Ok(Self {
            access_token,
            refresh_token,
            ikm,
            signature,
            expires_at,
        });
    }

    /// Returns true of the token is expired
    /// If the token is expired, it should be discarded
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        return now > self.expires_at;
    }

    /// Returns the public key for the signature
    pub fn get_signature_public_key(&self) -> Result<Vec<u8>, Error> {
        let public: [u8; CRYPTO_SIGN_PUBLICKEYBYTES as usize] = [0; CRYPTO_SIGN_PUBLICKEYBYTES as usize];
        let sk = self.signature.clone().as_mut_ptr();

        let result = unsafe { crypto_sign_ed25519_sk_to_pk(sk, public.as_ptr()) };
        if result == 0 {
            return Ok(public.as_ref().to_owned());
        }

        return Err(Error::TokenSignatureSize(format!("Signature secret key should be {} bytes", 64)));
    }
}