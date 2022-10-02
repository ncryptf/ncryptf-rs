use dryoc::{
    constants::{
        CRYPTO_SIGN_BYTES,
        CRYPTO_SIGN_SECRETKEYBYTES,
        CRYPTO_BOX_SECRETKEYBYTES,
        CRYPTO_BOX_PUBLICKEYBYTES,
        CRYPTO_BOX_NONCEBYTES,
        CRYPTO_SIGN_PUBLICKEYBYTES,
    },
    rng::randombytes_buf,
    classic::{
        crypto_sign::crypto_sign_detached,
        crypto_core::crypto_scalarmult_base,
    }, generichash::GenericHash
};
use libsodium_sys::crypto_sign_ed25519_sk_to_pk;
use libsodium_sys::crypto_box_easy;

use crate::{error::NcryptfError as Error, VERSION_2_HEADER};

pub struct Request {
    pub secret_key: Vec<u8>,
    pub signature_secret_key: Vec<u8>,
    pub nonce: Option<Vec<u8>>
}

impl Request {
    /// Encrypts a message with a given public key
    pub fn encrypt(&mut self, data: String, public_key: Vec<u8>) -> Result<Vec<u8>, Error> {
        return self.encrypt_with_nonce(data, public_key, None, Some(2));
    }

    /// Encrypts a message with a given public key, none, and version identifier
    pub fn encrypt_with_nonce(&mut self, data: String, public_key: Vec<u8>, nonce: Option<Vec<u8>>, version: Option<i32>) -> Result<Vec<u8>, Error> {
        let n = match nonce {
            Some(n) => n,
            None => randombytes_buf(32)
        };

        self.nonce = Some(n.clone());

        if public_key.len() != CRYPTO_BOX_PUBLICKEYBYTES {
            return Err(Error::InvalidArgument(format!("Public key should be {} bytes", CRYPTO_BOX_PUBLICKEYBYTES)));
        }

        if n.clone().len() != CRYPTO_BOX_NONCEBYTES {
           return Err(Error::InvalidArgument(format!("Nonce should be {} bytes", CRYPTO_BOX_NONCEBYTES)));
        }

        match version {
            Some(2) => {
                // Version 2 header is a fixed value
                let h = VERSION_2_HEADER;
                let header = hex::decode(h.to_string()).unwrap();
                let mut body = match self.encrypt_body(data.clone(), public_key, n.clone()) {
                    Ok(body) => body,
                    Err(error) => {
                        return Err(error)
                    }
                };

                // Extract the public key from the secret key
                let mut ipk: [u8; CRYPTO_BOX_PUBLICKEYBYTES] = vec![0; CRYPTO_BOX_PUBLICKEYBYTES].try_into().unwrap();
                let csk:[u8; CRYPTO_BOX_SECRETKEYBYTES] = self.secret_key.clone().try_into().unwrap();
                crypto_scalarmult_base(&mut ipk, &csk);

                // Convert the signature secret key, into a public key
                let mut isk: [u8; CRYPTO_SIGN_PUBLICKEYBYTES] = vec![0; CRYPTO_SIGN_PUBLICKEYBYTES].try_into().unwrap();
                let ssk: [u8; CRYPTO_SIGN_SECRETKEYBYTES] = self.signature_secret_key.clone().try_into().unwrap();
                let result = unsafe { crypto_sign_ed25519_sk_to_pk(isk.as_mut_ptr(), ssk.as_ptr()) };
                if result != 0 {
                    return Err(Error::EncryptError);
                }

                // Calculate the signature
                let mut signature = match self.sign(data.clone()) {
                    Ok(signature) => signature,
                    Err(error) => return Err(error)
                };

                let mut payload: Vec<u8> = Vec::<u8>::new();
                payload.append(&mut header.clone());
                payload.append(&mut n.clone());
                payload.append(&mut ipk.to_vec());
                payload.append(&mut body);
                payload.append(&mut isk.to_vec());
                payload.append(&mut signature);

                let s: &[u8; CRYPTO_BOX_NONCEBYTES] = &n.clone().try_into().unwrap();
                let mut hash: Vec<u8> = GenericHash::<CRYPTO_BOX_NONCEBYTES, 64>::hash(&payload, Some(s)).unwrap();

                payload.append(&mut hash);
                return Ok(payload);
            },
            _ => {
                return self.encrypt_body(data.clone(), public_key, n.clone());
            }
        }
    }

    /// Internal encryption method
    fn encrypt_body(&self, data: String, public_key: Vec<u8>, nonce: Vec<u8>) -> Result<Vec<u8>, Error> {
        let message = data.as_bytes();
        let mut ciphertext = Box::new(vec![0u8; message.len() + CRYPTO_BOX_NONCEBYTES]);
        let sk:[u8; CRYPTO_BOX_SECRETKEYBYTES] = self.secret_key.clone().try_into().unwrap();
        let pk: [u8; CRYPTO_BOX_PUBLICKEYBYTES] = public_key.clone().try_into().unwrap();
        let n: [u8; CRYPTO_BOX_NONCEBYTES] = nonce.clone().try_into().unwrap();

        let result: i32= unsafe {
            crypto_box_easy(
                ciphertext.as_mut_ptr(),
                message.as_ptr(),
                message.len().try_into().unwrap(),
                n.as_ptr(),
                pk.as_ptr(),
                sk.as_ptr()
            )
        };

        match result {
            0 => {
                let mut vec = ciphertext.to_vec();
                vec.retain(|x| *x != 0);
                return Ok(vec);
            },
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
        let mut signature = [0u8; CRYPTO_SIGN_BYTES];
        let key:[u8; CRYPTO_SIGN_SECRETKEYBYTES] = self.signature_secret_key.clone().try_into().unwrap();
        return match crypto_sign_detached(&mut signature, data.as_bytes(), &key) {
            Ok(_) =>{
                return Ok(signature.to_vec());
            },
            Err(_error) => {
                Err(Error::SignatureGenerationError)
            }
        }
    }

    /// Creates a new request from a given secret key and signature secret key
    pub fn from(secret_key: Vec<u8>, signature_secret_key: Vec<u8>) -> Result<Self, Error> {
        if secret_key.len() != CRYPTO_BOX_SECRETKEYBYTES {
            return Err(Error::InvalidArgument(format!("Secret key should be {} bytes", CRYPTO_BOX_SECRETKEYBYTES)));
        }
        if signature_secret_key.len() != CRYPTO_SIGN_SECRETKEYBYTES {
            return Err(Error::InvalidArgument(format!("Signature key should be {} bytes", CRYPTO_SIGN_SECRETKEYBYTES)));
        }

        return Ok(Request {
            secret_key,
            signature_secret_key,
            nonce: None
        });
    }

}