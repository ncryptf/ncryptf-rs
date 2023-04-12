use libsodium_sys::{
    crypto_box_MACBYTES as CRYPTO_BOX_MACBYTES, crypto_box_NONCEBYTES as CRYPTO_BOX_NONCEBYTES,
    crypto_box_PUBLICKEYBYTES as CRYPTO_BOX_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES as CRYPTO_BOX_SECRETKEYBYTES, crypto_box_easy, crypto_generichash,
    crypto_scalarmult_base, crypto_sign_BYTES as CRYPTO_SIGN_BYTES,
    crypto_sign_PUBLICKEYBYTES as CRYPTO_SIGN_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES as CRYPTO_SIGN_SECRETKEYBYTES, crypto_sign_detached,
    crypto_sign_ed25519_sk_to_pk,
};

use crate::{error::NcryptfError as Error, util::randombytes_buf, VERSION_2_HEADER};

/// A request that emits a encrypted string for submission to the server.
pub struct Request {
    secret_key: Vec<u8>,
    signature_secret_key: Vec<u8>,
    nonce: Option<Vec<u8>>,
    message: Option<Vec<u8>>,
}

impl Request {
    /// Encrypts a message with a given public key
    pub fn encrypt(&mut self, data: String, public_key: Vec<u8>) -> Result<Vec<u8>, Error> {
        match self.encrypt_with_nonce(data, public_key, None, Some(2)) {
            Ok(result) => {
                self.message = Some(result.clone());
                return Ok(result);
            }
            Err(error) => return Err(error),
        };
    }

    /// Returns the message, if it has been set
    pub fn get_message(&self) -> Option<Vec<u8>> {
        return self.message.clone();
    }

    /// Encrypts a message with a given public key, none, and version identifier
    pub fn encrypt_with_nonce(
        &mut self,
        data: String,
        public_key: Vec<u8>,
        nonce: Option<Vec<u8>>,
        version: Option<i8>,
    ) -> Result<Vec<u8>, Error> {
        let n = match nonce {
            Some(n) => n,
            None => randombytes_buf(CRYPTO_BOX_NONCEBYTES as usize),
        };

        self.nonce = Some(n.clone());

        if public_key.len() != (CRYPTO_BOX_PUBLICKEYBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Public key should be {} bytes",
                CRYPTO_BOX_PUBLICKEYBYTES
            )));
        }

        if n.clone().len() != (CRYPTO_BOX_NONCEBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Nonce should be {} bytes",
                CRYPTO_BOX_NONCEBYTES
            )));
        }

        match version {
            Some(2) => {
                // Version 2 header is a fixed value
                let h = VERSION_2_HEADER;
                let header = hex::decode(h.to_string()).unwrap();
                let mut body = match self.encrypt_body(data.clone(), public_key, n.clone()) {
                    Ok(body) => body,
                    Err(error) => return Err(error),
                };

                // Extract the public key from the secret key
                let mut ipk: [u8; CRYPTO_BOX_PUBLICKEYBYTES as usize] =
                    vec![0; CRYPTO_BOX_PUBLICKEYBYTES as usize]
                        .try_into()
                        .unwrap();
                let csk: [u8; CRYPTO_BOX_SECRETKEYBYTES as usize] =
                    self.secret_key.clone().try_into().unwrap();
                let _result = unsafe { crypto_scalarmult_base(ipk.as_mut_ptr(), csk.as_ptr()) };

                if _result != 0 {
                    return Err(Error::EncryptError);
                }

                // Convert the signature secret key, into a public key
                let mut isk: [u8; CRYPTO_SIGN_PUBLICKEYBYTES as usize] =
                    vec![0; CRYPTO_SIGN_PUBLICKEYBYTES as usize]
                        .try_into()
                        .unwrap();
                let ssk: [u8; CRYPTO_SIGN_SECRETKEYBYTES as usize] =
                    self.signature_secret_key.clone().try_into().unwrap();
                let _result =
                    unsafe { crypto_sign_ed25519_sk_to_pk(isk.as_mut_ptr(), ssk.as_ptr()) };
                if _result != 0 {
                    return Err(Error::EncryptError);
                }

                // Calculate the signature
                let mut signature = match self.sign(data.clone()) {
                    Ok(signature) => signature,
                    Err(error) => return Err(error),
                };

                let mut payload: Vec<u8> = Vec::<u8>::new();
                payload.append(&mut header.clone());
                payload.append(&mut n.clone());
                payload.append(&mut ipk.to_vec());
                payload.append(&mut body);
                payload.append(&mut isk.to_vec());
                payload.append(&mut signature);

                let s: &[u8; CRYPTO_BOX_NONCEBYTES as usize] = &n.clone().try_into().unwrap();
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
                    return Err(Error::EncryptError);
                }

                payload.append(&mut hash.to_vec());
                return Ok(payload);
            }
            _ => {
                return self.encrypt_body(data.clone(), public_key, n.clone());
            }
        }
    }

    /// Internal encryption method
    fn encrypt_body(
        &self,
        data: String,
        public_key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let message = data.into_bytes();
        let len = message.len();

        let mut ciphertext = Box::new(vec![0u8; len + (CRYPTO_BOX_MACBYTES as usize)]);
        let sk: [u8; CRYPTO_BOX_SECRETKEYBYTES as usize] =
            self.secret_key.clone().try_into().unwrap();
        let pk: [u8; CRYPTO_BOX_PUBLICKEYBYTES as usize] = public_key.clone().try_into().unwrap();
        let n: [u8; CRYPTO_BOX_NONCEBYTES as usize] = nonce.clone().try_into().unwrap();

        let result: i32 = unsafe {
            crypto_box_easy(
                ciphertext.as_mut_ptr(),
                message.as_ptr(),
                message.len().try_into().unwrap(),
                n.as_ptr(),
                pk.as_ptr(),
                sk.as_ptr(),
            )
        };

        match result {
            0 => {
                return Ok(ciphertext.to_vec());
            }
            _ => {
                return Err(Error::DecryptError);
            }
        }
    }

    /// Returns the nonce
    pub fn get_nonce(&self) -> Option<Vec<u8>> {
        return self.nonce.clone();
    }

    /// Signs the given data, then returns a detached signature
    pub fn sign(&self, data: String) -> Result<Vec<u8>, Error> {
        let mut signature = [0u8; (CRYPTO_SIGN_BYTES as usize)];
        let key: [u8; CRYPTO_SIGN_SECRETKEYBYTES as usize] =
            self.signature_secret_key.clone().try_into().unwrap();

        let mut signature_size = signature.len() as u64;
        let _result = unsafe {
            crypto_sign_detached(
                signature.as_mut_ptr(),
                &mut signature_size,
                data.as_ptr(),
                data.len() as u64,
                key.as_ptr(),
            )
        };

        if _result != 0 {
            return Err(Error::EncryptError);
        }

        return Ok(signature.to_vec());
    }

    /// Creates a new request from a given secret key and signature secret key
    pub fn from(secret_key: Vec<u8>, signature_secret_key: Vec<u8>) -> Result<Self, Error> {
        if secret_key.len() != (CRYPTO_BOX_SECRETKEYBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Secret key should be {} bytes",
                CRYPTO_BOX_SECRETKEYBYTES
            )));
        }
        if signature_secret_key.len() != (CRYPTO_SIGN_SECRETKEYBYTES as usize) {
            return Err(Error::InvalidArgument(format!(
                "Signature key should be {} bytes",
                CRYPTO_SIGN_SECRETKEYBYTES
            )));
        }

        return Ok(Request {
            secret_key,
            signature_secret_key,
            nonce: None,
            message: None,
        });
    }
}
