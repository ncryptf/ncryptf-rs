use std::time::Duration;
use rocket::tokio;
use stretto::AsyncCache;

const NCRYPTF_CONTENT_TYPE: &str = "application/vnd.ncryptf+json";
const NCRYPTF_DRIFT_ALLOWANCE: i32 = 90;
//AsyncCache<&str, &str> = AsyncCache::new(12960, 1e6 as i64, tokio::spawn).unwrap()

mod json;
pub use json::Json;
//mod request;
//mod authentication;