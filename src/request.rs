use dryoc::classic::crypto_box;
use dryoc::classic::crypto_sign;
use dryoc::classic::crypto_core;
use dryoc::generichash::GenericHash;
use dryoc::sign::SigningKeyPair;
use dryoc::constants::{
    CRYPTO_BOX_MACBYTES, CRYPTO_BOX_NONCEBYTES, CRYPTO_BOX_PUBLICKEYBYTES,
    CRYPTO_BOX_SECRETKEYBYTES, CRYPTO_SIGN_BYTES, CRYPTO_SIGN_PUBLICKEYBYTES,
    CRYPTO_SIGN_SECRETKEYBYTES
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

                // Extract the public key from the secret key using scalar multiplication
                let csk: [u8; CRYPTO_BOX_SECRETKEYBYTES as usize] =
                    self.secret_key.clone().try_into().unwrap();
                let mut ipk = [0u8; CRYPTO_BOX_PUBLICKEYBYTES as usize];
                crypto_core::crypto_scalarmult_base(&mut ipk, &csk);

                // Convert the signature secret key, into a public key
                let ssk: [u8; CRYPTO_SIGN_SECRETKEYBYTES as usize] =
                    self.signature_secret_key.clone().try_into().unwrap();
                let keypair: SigningKeyPair<[u8; CRYPTO_SIGN_PUBLICKEYBYTES as usize], [u8; CRYPTO_SIGN_SECRETKEYBYTES as usize]> = SigningKeyPair::from_secret_key(ssk);
                let isk = keypair.public_key;

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
                
                let hash: [u8; 64] = GenericHash::hash(&input, Some(s))
                    .map_err(|_| Error::EncryptError)?;

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
        let sk: [u8; CRYPTO_BOX_SECRETKEYBYTES as usize] =
            self.secret_key.clone().try_into().unwrap();
        let pk: [u8; CRYPTO_BOX_PUBLICKEYBYTES as usize] = public_key.clone().try_into().unwrap();
        let n: [u8; CRYPTO_BOX_NONCEBYTES as usize] = nonce.clone().try_into().unwrap();

        let mut ciphertext = vec![0u8; message.len() + CRYPTO_BOX_MACBYTES as usize];
        crypto_box::crypto_box_easy(
            &mut ciphertext,
            &message,
            &n,
            &pk,
            &sk,
        ).map_err(|_| Error::EncryptError)?;

        return Ok(ciphertext);
    }

    /// Returns the nonce
    pub fn get_nonce(&self) -> Option<Vec<u8>> {
        return self.nonce.clone();
    }

    /// Signs the given data, then returns a detached signature
    pub fn sign(&self, data: String) -> Result<Vec<u8>, Error> {
        let key: [u8; CRYPTO_SIGN_SECRETKEYBYTES as usize] =
            self.signature_secret_key.clone().try_into().unwrap();

        let mut signature = [0u8; CRYPTO_SIGN_BYTES as usize];
        crypto_sign::crypto_sign_detached(
            &mut signature,
            data.as_bytes(),
            &key,
        ).map_err(|_| Error::EncryptError)?;

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
