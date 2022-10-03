use crate::{token::Token, signature::Signature};
use crate::error::NcryptfError as Error;
use chrono::Timelike;
use chrono::{
    DateTime,
    offset::Utc
};
use serde::{Serialize, Deserialize};
use sha2::Sha256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use dryoc::rng::randombytes_buf;

const AUTH_INFO: &str = "HMAC|AuthenticationKey";

#[derive(Debug, Clone)]
pub struct Authorization {
    pub token: Token,
    pub salt: Vec<u8>,
    pub date: DateTime<Utc>,
    pub signature: String,
    pub hmac: Vec<u8>,
    pub version: Option<i8>
}

impl Authorization {
    /// Generates an Authorization struct from the given parameters
    pub fn from(
        method: String,
        uri: String,
        token: Token,
        date: DateTime<Utc>,
        payload: String,
        salt: Option<Vec<u8>>,
        version: Option<i8>
    ) -> Result<Self, Error> {
        let m = method.to_uppercase();
        let s = match salt {
            Some(s) => s,
            None => randombytes_buf(32)
        };

        let sr: &[u8; 32] = &s.clone().try_into().unwrap();
        let ikm: &[u8; 32] = &token.clone().ikm.try_into().unwrap();
        let signature = Signature::derive(m, uri, s.clone(), date, payload, version);
        let hkdf = Hkdf::<Sha256>::new(Some(sr), ikm);
        let mut okm = [0u8; 32];
        match hkdf.expand(&AUTH_INFO.as_bytes(),&mut okm) {
            Err(_) => {
                return Err(Error::InvalidArgument(format!("Unable to generate HMAC for token.")));
            },
            Ok(_) => {}
        };

        let hk = okm.to_vec();
        let hkdf_string = hex::encode(hk).to_string().to_lowercase();

        let mut hmac = Hmac::<Sha256>::new_from_slice(hkdf_string.as_bytes())
            .expect("HMAC can take key of any size");
        hmac.update(signature.as_bytes());
        let result = hmac.finalize();
        let bytes = result.into_bytes();
        return Ok(Authorization {
            token,
            salt: s.clone(),
            date,
            signature,
            hmac: bytes.to_vec(),
            version
        });
    }

    /// Returns the date
    pub fn get_date(&self) -> DateTime<Utc> {
        return self.date;
    }

    /// Returns the date as a string
    pub fn get_date_string(&self) -> String {
        return self.date.to_rfc2822();
    }

    /// Returns the raw HMAC
    pub fn get_hmac(&self) -> Vec<u8> {
        return self.hmac.clone();
    }

    /// Returns the base64 encoded HMAC
    pub fn get_encoded_hmac(&self) -> String {
        let hmac = self.get_hmac();
        return base64::encode(hmac);
    }

    /// Returns the base64 encoded salt
    pub fn get_encoded_salt(&self) -> String {
        let salt = self.salt.clone();
        return base64::encode(salt);
    }

    /// Returns the signature string
    pub fn get_signature_string(&self) -> String {
        return self.signature.clone();
    }

    /// Returns the time drift between the current time and the provided time
    pub fn get_time_drift(date: DateTime<Utc>) -> u32 {
        let now = Utc::now();
        return now.second().abs_diff(date.second());
    }

    /// Verifies whether or not a given HMAC is equal to the one on record
    /// This comparison occurs in constant time to avoid timing attack
    pub fn verify(&self, hmac: Vec<u8>, drift_allowance: u32) -> bool {
        let drift = Self::get_time_drift(self.get_date());
        if drift >= drift_allowance {
            return false;
        }

        if constant_time_eq::constant_time_eq(&hmac, &self.get_hmac()) {
            return true;
        }

        return false;
    }

    /// Returns the authorization header as a string
    pub fn get_header(&self) -> String {
        let salt = self.get_encoded_salt();
        let hmac = self.get_encoded_hmac();

        match self.version {
            Some(2) => {
                let d = AuthStruct{
                    access_token: self.token.access_token.clone(),
                    date: self.get_date_string(),
                    hmac: hmac.clone(),
                    salt: salt.clone(),
                    v: 2
                };

                // The double escape is for library compatability with tests
                let json = serde_json::to_string(&d).unwrap().to_string().replace("/", "\\/");
                return format!("HMAC {}", base64::encode(json));
            },
            _ => {
                return format!("HMAC {},{},{}", self.token.access_token, hmac, salt);
            }
        };
    }
}

/// Internal structure for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthStruct {
    pub access_token: String,
    pub date: String,
    pub hmac: String,
    pub salt: String,
    pub v: i8
}