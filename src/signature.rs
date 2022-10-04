extern crate base64;
use chrono::{
    DateTime,
    offset::Utc
};

use libsodium_sys::{
    crypto_sign_keypair,
    crypto_generichash,
    crypto_sign_PUBLICKEYBYTES as CRYPTO_SIGN_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES as CRYPTO_SIGN_SECRETKEYBYTES
};

use crate::Keypair;

#[derive(Debug, Clone)]
pub struct Signature;

impl Signature {
    /// Derives a signature from the given parameters
    pub fn derive(
        method: String,
        uri: String,
        salt: Vec<u8>,
        datetime:DateTime<Utc>,
        payload: String,
        version: Option<i8>
    ) -> String {
        let hash = Self::get_signature_hash(payload, salt.clone(), version);
        let b64s = base64::encode(salt);
        let ts = datetime.to_rfc2822();

        return format!("{}\n{}+{}\n{}\n{}", hash, method, uri, ts, b64s);
    }

    /// Generates a new random signature
    pub fn new() -> Keypair {
        let mut sk: [u8; CRYPTO_SIGN_SECRETKEYBYTES as usize] = vec![0; CRYPTO_SIGN_SECRETKEYBYTES as usize].try_into().unwrap();
        let mut pk: [u8; CRYPTO_SIGN_PUBLICKEYBYTES as usize] = vec![0; CRYPTO_SIGN_PUBLICKEYBYTES as usize].try_into().unwrap();
        
        let _result = unsafe { crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())};
        
        return Keypair {
            secret_key: sk.to_vec(),
            public_key: pk.to_vec()
        }
    }

    /// Generates a signature hash given a salt and data
    pub fn get_signature_hash(data: String, salt: Vec<u8>, version: Option<i8>) -> String {
        match version {
            Some(2) => {
                let s: &[u8; 32] = &salt.try_into().unwrap();
                let input = data.as_bytes();
                let mut hash: [u8; 64] = vec![0; 64].try_into().unwrap();

                let _result = unsafe { crypto_generichash(
                    hash.as_mut_ptr(),
                    64,
                    input.as_ptr(),
                    input.len() as u64,
                    s.as_ptr(),
                    32
                ) };

                return base64::encode(&hash);
            },
            _ => {
                return sha256::digest(data);
            }
        }
    }
}