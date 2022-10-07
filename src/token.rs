use libsodium_sys::{
    crypto_sign_ed25519_sk_to_pk,
    crypto_sign_PUBLICKEYBYTES as CRYPTO_SIGN_PUBLICKEYBYTES
};

use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::NcryptfError as Error;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Given a serde_json::Value, will attempt to return a token
    pub fn from_json(json: serde_json::Value) -> Result<Self, Error> {
        if json.get("access_token").is_none()  ||
        json.get("refresh_token").is_none() ||
        json.get("ikm").is_none() ||
        json.get("signing").is_none() ||
        json.get("expires_at").is_none() {
            return Err(Error::InvalidArgument(format!("The provided JSON object is not valid for tokenization.")));
        }

        return match Token::from(
            json.get("access_token").unwrap().to_string(),
            json.get("refresh_token").unwrap().to_string(),
            base64::decode(json.get("ikm").unwrap().as_str().unwrap()).unwrap(),
            base64::decode(json.get("signing").unwrap().as_str().unwrap()).unwrap(),
            json.get("expires_at").unwrap().as_u64().unwrap()
        ) {
            Ok(token) => return Ok(token),
            Err(_error) => Err(_error)
        }
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
        let public: [u8; (CRYPTO_SIGN_PUBLICKEYBYTES as usize) as usize] = [0; (CRYPTO_SIGN_PUBLICKEYBYTES as usize)];
        let sk = self.signature.clone().as_mut_ptr();

        let result = unsafe { crypto_sign_ed25519_sk_to_pk(sk, public.as_ptr()) };
        if result == 0 {
            return Ok(public.as_ref().to_owned());
        }

        return Err(Error::TokenSignatureSize(format!("Signature secret key should be {} bytes", 64)));
    }
}