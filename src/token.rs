use chrono::Utc;
use dryoc::constants::{
    CRYPTO_SIGN_PUBLICKEYBYTES,
    CRYPTO_SIGN_SECRETKEYBYTES
};
use dryoc::sign::SigningKeyPair;
use base64::{Engine as _, engine::general_purpose};

use crate::error::NcryptfError as Error;
use serde::{Deserialize, Serialize};

/// Authorization token data to be either stored locally, or server side in a cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub refresh_token: String,
    pub ikm: Vec<u8>,
    pub signature: Vec<u8>,
    pub expires_at: i64,
}

impl Token {
    /// Creates a new token with a given lifetime
    pub fn new(lifetime: i64) -> Token {
        let now = Utc::now().timestamp();
        let expires_at: i64;
        if lifetime >= 0 {
            expires_at = now + lifetime;
        } else {
            expires_at = now;
        }

        return Self {
            access_token: general_purpose::URL_SAFE.encode(crate::util::randombytes_buf(48)),
            refresh_token: general_purpose::URL_SAFE.encode(crate::util::randombytes_buf(64)),
            ikm: crate::util::randombytes_buf(32),
            signature: crate::util::randombytes_buf(64),
            expires_at: expires_at,
        };
    }

    /// Creates a new token from the provided values
    pub fn from(
        access_token: String,
        refresh_token: String,
        ikm: Vec<u8>,
        signature: Vec<u8>,
        expires_at: i64,
    ) -> Result<Token, Error> {
        if ikm.len() != 32 {
            return Err(Error::InvalidArgument(format!(
                "Initial key material should be {} bytes",
                32
            )));
        }

        if signature.len() != 64 {
            return Err(Error::InvalidArgument(format!(
                "Signature secret key should be {} bytes",
                64
            )));
        }

        return Ok(Self {
            access_token,
            refresh_token,
            ikm,
            signature,
            expires_at,
        });
    }

    /// Given a serde_json::Value, will attempt to return a token
    pub fn from_json(json: serde_json::Value) -> Result<Self, Error> {
        if json.get("access_token").is_none()
            || json.get("refresh_token").is_none()
            || json.get("ikm").is_none()
            || json.get("signing").is_none()
            || json.get("expires_at").is_none()
        {
            return Err(Error::InvalidArgument(format!(
                "The provided JSON object is not valid for tokenization."
            )));
        }

        return match Token::from(
            json.get("access_token").unwrap().to_string(),
            json.get("refresh_token").unwrap().to_string(),
            general_purpose::STANDARD.decode(json.get("ikm").unwrap().as_str().unwrap()).unwrap(),
            general_purpose::STANDARD.decode(json.get("signing").unwrap().as_str().unwrap()).unwrap(),
            json.get("expires_at").unwrap().as_i64().unwrap(),
        ) {
            Ok(token) => return Ok(token),
            Err(_error) => Err(_error),
        };
    }

    /// Returns true of the token is expired
    /// If the token is expired, it should be discarded
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp();
        return now > self.expires_at;
    }

    /// Returns the public key for the signature
    pub fn get_signature_public_key(&self) -> Result<Vec<u8>, Error> {
        if self.signature.len() != CRYPTO_SIGN_SECRETKEYBYTES {
            return Err(Error::TokenSignatureSize(format!(
                "Signature secret key should be {} bytes",
                CRYPTO_SIGN_SECRETKEYBYTES
            )));
        }

        // Convert Vec<u8> to fixed-size array
        let mut secret_key_bytes = [0u8; CRYPTO_SIGN_SECRETKEYBYTES];
        secret_key_bytes.copy_from_slice(&self.signature);

        let keypair: SigningKeyPair<[u8; CRYPTO_SIGN_PUBLICKEYBYTES], [u8; CRYPTO_SIGN_SECRETKEYBYTES]> = SigningKeyPair::from_secret_key(secret_key_bytes);

        return Ok(keypair.public_key.to_vec());
    }
}
