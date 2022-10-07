const NCRYPTF_CONTENT_TYPE: &str = "application/vnd.ncryptf+json";
const NCRYPTF_DRIFT_ALLOWANCE: i32 = 90;

#[derive(Debug, Clone)]
pub struct RequestPublicKey(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct RequestSigningPublicKey(pub Vec<u8>);

mod json;
pub use json::Json;
mod ek;
pub use ek::EncryptionKey;
mod fairing;
pub use fairing::Fairing;