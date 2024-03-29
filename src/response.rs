use constant_time_eq::constant_time_eq;
use libsodium_sys::{
    crypto_box_MACBYTES as CRYPTO_BOX_MACBYTES, crypto_box_NONCEBYTES as CRYPTO_BOX_NONCEBYTES,
    crypto_box_PUBLICKEYBYTES as CRYPTO_BOX_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES as CRYPTO_BOX_SECRETKEYBYTES, crypto_box_open_easy,
    crypto_generichash, crypto_sign_BYTES as CRYPTO_SIGN_BYTES,
    crypto_sign_PUBLICKEYBYTES as CRYPTO_SIGN_PUBLICKEYBYTES, crypto_sign_verify_detached,
};

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

        let mut message = Box::new(vec![
            0;
            response.clone().len() - (CRYPTO_BOX_MACBYTES as usize)
        ]);
        let sk: [u8; CRYPTO_BOX_SECRETKEYBYTES as usize] =
            self.secret_key.clone().try_into().unwrap();
        let pk: [u8; CRYPTO_BOX_PUBLICKEYBYTES as usize] = public_key.try_into().unwrap();
        let n: [u8; CRYPTO_BOX_NONCEBYTES as usize] = nonce.try_into().unwrap();

        let result: i32 = unsafe {
            crypto_box_open_easy(
                message.as_mut_ptr(),
                response.clone().as_ptr(),
                response.len().try_into().unwrap(),
                n.as_ptr(),
                pk.as_ptr(),
                sk.as_ptr(),
            )
        };

        match result {
            0 => {
                let v = message.to_vec().to_owned();
                let string = String::from_utf8(v).unwrap();
                let res = string.trim_matches(char::from(0)).to_string();
                return Ok(res);
            }
            _ => {
                return Err(Error::DecryptError);
            }
        }
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
        let mut hash: [u8; 64] = vec![0; 64].try_into().unwrap();

        let _result = unsafe {
            crypto_generichash(
                hash.as_mut_ptr(),
                64,
                input.as_ptr(),
                input.len() as u64,
                s.as_ptr(),
                CRYPTO_BOX_NONCEBYTES as usize,
            )
        };

        if _result != 0 {
            return Err(Error::DecryptError);
        }

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
        let result = unsafe {
            crypto_sign_verify_detached(
                sig.as_ptr(),
                response.as_ptr(),
                response.len() as u64,
                pk.as_ptr(),
            )
        };

        match result {
            0 => return Ok(true),
            _ => return Ok(false),
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
