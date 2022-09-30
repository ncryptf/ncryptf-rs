extern crate base64;
use dryoc::generichash::GenericHash;

#[derive(Debug, Clone)]
pub struct Signature;

impl Signature {
    /// Derives a signature from the given parameters
    pub fn derive(
        method: String,
        uri: String,
        salt: Vec<u8>,
        datetime: chrono::DateTime<chrono::offset::Utc>,
        payload: String,
        version: Option<i8>
    ) -> String {
        let hash = Self::get_signature_hash(payload, salt.clone(), version);
        let b64s = base64::encode(salt);
        let ts = datetime.to_rfc2822();

        return format!("{}\n{}+{}\n{}\n{}", hash, method, uri, ts, b64s);
    }

    /// Generates a signature hash given a salt and data
    pub fn get_signature_hash(data: String, salt: Vec<u8>, version: Option<i8>) -> String {
        match version {
            Some(2) => {
                let s: &[u8; 32] = &salt.try_into().unwrap();
                let input = data.as_bytes();
                let hash: Vec<u8> = GenericHash::<32, 64>::hash(input, Some(s)).unwrap();

                return base64::encode(&hash);
            },
            _ => {
                return sha256::digest(data);
            }
        }
    }
}