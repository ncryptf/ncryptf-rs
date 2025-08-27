use constant_time_eq::constant_time_eq;
use dryoc::constants::{
    CRYPTO_BOX_MACBYTES,
    CRYPTO_BOX_NONCEBYTES,
    CRYPTO_BOX_PUBLICKEYBYTES,
    CRYPTO_BOX_SECRETKEYBYTES,
    CRYPTO_SIGN_BYTES,
    CRYPTO_SIGN_PUBLICKEYBYTES
};
use dryoc::classic::crypto_box;
use dryoc::classic::crypto_sign;
use dryoc::generichash::GenericHash;

use crate::{error::NcryptfError as Error, VERSION_2_HEADER};

/// Response allows for decrypting of a request
pub struct Response {
    pub secret_key: Vec<u8>,
}

impl Response {
    /// Decrypts a response
    pub fn decrypt(
        &self,
        response: Vec<u8>,
        public_key: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
    ) -> Result<String, Error> {
        // Extract the nonce if one isn't provided
        let n = match nonce {
            Some(nonce) => nonce,
            None => response.get(4..28).unwrap().to_vec(),
        };

        return self.decrypt_body(response, public_key, n.clone());
    }

    fn decrypt_body(
        &self,
        response: Vec<u8>,
        public_key: Option<Vec<u8>>,
        nonce: Vec<u8>,
    ) -> Result<String, Error> {
        if nonce.len() != (CRYPTO_BOX_NONCEBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Nonce should be {} bytes",
                CRYPTO_BOX_NONCEBYTES
            )));
        }

        let r = response.clone();
        match Self::get_version(r) {
            Ok(version) => match version {
                2 => return self.decrypt_v2(response, nonce),
                _ => return self.decrypt_v1(response, public_key.unwrap(), nonce),
            },
            Err(error) => return Err(error),
        };
    }

    fn decrypt_v1(
        &self,
        response: Vec<u8>,
        public_key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<String, Error> {
        if public_key.len() != (CRYPTO_BOX_PUBLICKEYBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Public key should be {} bytes",
                CRYPTO_BOX_NONCEBYTES
            )));
        }

        if response.len() < (CRYPTO_BOX_MACBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Response is too short to be decrypted"
            )));
        }

        let sk: [u8; CRYPTO_BOX_SECRETKEYBYTES as usize] =
            self.secret_key.clone().try_into().unwrap();
        let pk: [u8; CRYPTO_BOX_PUBLICKEYBYTES as usize] = public_key.try_into().unwrap();
        let n: [u8; CRYPTO_BOX_NONCEBYTES as usize] = nonce.try_into().unwrap();

        let mut message = vec![0u8; response.len() - CRYPTO_BOX_MACBYTES as usize];
        crypto_box::crypto_box_open_easy(
            &mut message,
            &response,
            &n,
            &pk,
            &sk,
        ).map_err(|_| Error::DecryptError)?;

        let string = String::from_utf8(message).map_err(|_| Error::DecryptError)?;
        return Ok(string);
    }

    fn decrypt_v2(&self, response: Vec<u8>, nonce: Vec<u8>) -> Result<String, Error> {
        let length = response.len();
        if length < 236 {
            return Err(Error::InvalidArgument(format!(
                "Response length is too short for a v2 response."
            )));
        }

        let payload = response.get(0..length - 64).unwrap().to_vec();
        let checksum = response.get(length - 64..length).unwrap().to_vec();

        let s: &[u8; CRYPTO_BOX_NONCEBYTES as usize] = &nonce.clone().try_into().unwrap();
        let input = payload.clone();
        
        let hash: [u8; 64] = GenericHash::hash(&input, Some(s))
            .map_err(|_| Error::DecryptError)?;

        // Verify that the checksum hasn't been tampered with
        if !constant_time_eq(&checksum, &hash) {
            return Err(Error::DecryptError);
        }

        let public_key = Self::get_public_key_from_response(response.clone()).unwrap();
        let payload_len = payload.len();
        let signature = payload.get(payload_len - 64..payload_len).unwrap().to_vec();
        let signature_public_key = Self::get_signing_public_key_from_response(response).unwrap();
        let body = payload.get(60..payload_len - 96).unwrap().to_vec();

        let decrypted = self.decrypt_v1(body, public_key, nonce.clone())?;

        Self::is_signature_valid(decrypted.clone(), signature, signature_public_key)?;

        return Ok(decrypted);
    }

    /// Returns true if the signature is valid for the response
    pub fn is_signature_valid(
        response: String,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<bool, Error> {
        if signature.len() != (CRYPTO_SIGN_BYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Signature must be {} bytes",
                CRYPTO_SIGN_BYTES
            )));
        }

        if public_key.len() != (CRYPTO_SIGN_PUBLICKEYBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Public key must be {} bytes",
                CRYPTO_SIGN_PUBLICKEYBYTES
            )));
        }

        let sig: [u8; CRYPTO_SIGN_BYTES as usize] = signature.try_into().unwrap();
        let pk: [u8; CRYPTO_SIGN_PUBLICKEYBYTES as usize] = public_key.try_into().unwrap();
        
        let result = crypto_sign::crypto_sign_verify_detached(
            &sig,
            response.as_bytes(),
            &pk,
        );

        match result {
            Ok(_) => return Ok(true),
            Err(_) => return Ok(false),
        };
    }

    ///  Extracts the public key from a v2 response
    pub fn get_public_key_from_response(response: Vec<u8>) -> Result<Vec<u8>, Error> {
        match Self::get_version(response.clone()) {
            Ok(version) => match version {
                2 => {
                    let length = response.len();
                    if length < 236 {
                        return Err(Error::InvalidArgument(format!("Message is too short.")));
                    }

                    return Ok(response.get(28..60).unwrap().to_vec());
                }
                _ => {
                    return Err(Error::InvalidArgument(format!(
                        "The response provided is not suitable for public key extraction."
                    )));
                }
            },
            _ => {
                return Err(Error::InvalidArgument(format!(
                    "The response provided is not suitable for public key extraction."
                )));
            }
        }
    }

    /// Extracts the public signing key from a v2 response
    pub fn get_signing_public_key_from_response(response: Vec<u8>) -> Result<Vec<u8>, Error> {
        match Self::get_version(response.clone()) {
            Ok(version) => match version {
                2 => {
                    let length = response.len();
                    if length < 236 {
                        return Err(Error::InvalidArgument(format!("Message is too short.")));
                    }

                    return Ok(response
                        .get(length - 160..(length - 160 + 32))
                        .unwrap()
                        .to_vec());
                }
                _ => {
                    return Err(Error::InvalidArgument(format!(
                        "The response provided is not suitable for public key extraction."
                    )));
                }
            },
            _ => {
                return Err(Error::InvalidArgument(format!(
                    "The response provided is not suitable for public key extraction."
                )));
            }
        }
    }

    /// Returns the version information from the string
    pub fn get_version(response: Vec<u8>) -> Result<i32, Error> {
        if response.len() < 16 {
            return Err(Error::InvalidArgument(format!(
                "Message length is too short to determine version"
            )));
        }

        match response.get(0..4) {
            Some(header) => {
                let s = hex::encode(header.to_vec()).to_string().to_uppercase();

                if s.as_str().eq(VERSION_2_HEADER) {
                    return Ok(2);
                }

                return Ok(1);
            }
            _ => {
                return Ok(1);
            }
        }
    }

    /// Creates a response from the secret key
    pub fn from(secret_key: Vec<u8>) -> Result<Self, Error> {
        if secret_key.len() != (CRYPTO_BOX_SECRETKEYBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Secret key should be {} bytes",
                CRYPTO_BOX_SECRETKEYBYTES
            )));
        }

        return Ok(Response { secret_key });
    }
}
