const NCRYPTF_CONTENT_TYPE: &str = "application/vnd.ncryptf+json";
const NCRYPTF_DRIFT_ALLOWANCE: i32 = 90;

mod json;
pub use json::Json;
mod ek;
pub use ek::EncryptionKey;
//mod authentication;