use rocket::Request;

/// The Ncryptf JSON content type
pub const NCRYPTF_CONTENT_TYPE: &str = "application/vnd.ncryptf+json";

/// The amount of time (in either direction) a request time may differ by and still be accepted.
pub const NCRYPTF_DRIFT_ALLOWANCE: i32 = 90;

/// The cached public key from the request
pub struct RequestPublicKey(pub Vec<u8>);

/// The cached signing public key from the request
pub struct RequestSigningPublicKey(pub Vec<u8>);

mod json;
pub use json::{respond_to_with_ncryptf, Error as JsonError, Json, JsonResponse, parse_body};
mod ek;
pub use ek::{EncryptionKey, ExportableEncryptionKeyData};
mod auth;
pub use auth::{AuthorizationTrait, TokenError, RequestData, *};

use cached::{Cached, IOCached};
use std::sync::{Arc, Mutex};

/// A wrapper for supported cache types
pub enum CacheWrapper {
    TimedCache(Arc<Mutex<cached::TimedCache<String, EncryptionKey>>>),
    UnboundCache(Arc<Mutex<cached::UnboundCache<String, EncryptionKey>>>),
    RedisCache(Arc<Mutex<cached::RedisCache<String, EncryptionKey>>>),
}

impl CacheWrapper {
    pub fn get(&self, key: &str) -> Option<EncryptionKey> {
        match self {
            CacheWrapper::TimedCache(cache) => {
                let mut guard = cache.lock().ok()?;
                guard.cache_get(&key.to_string()).cloned()
            }
            CacheWrapper::UnboundCache(cache) => {
                let mut guard = cache.lock().ok()?;
                guard.cache_get(&key.to_string()).cloned()
            }
            CacheWrapper::RedisCache(cache) => {
                let guard = cache.lock().ok()?;
                match guard.cache_get(&key.to_string()) {
                    Ok(value) => value,
                    Err(_) => None,
                }
            }
        }
    }
    
    pub fn set(&self, key: String, value: EncryptionKey) {
        match self {
            CacheWrapper::TimedCache(cache) => {
                if let Ok(mut guard) = cache.lock() {
                    guard.cache_set(key, value);
                }
            }
            CacheWrapper::UnboundCache(cache) => {
                if let Ok(mut guard) = cache.lock() {
                    guard.cache_set(key, value);
                }
            }
            CacheWrapper::RedisCache(cache) => {
                if let Ok(guard) = cache.lock() {
                    let _ = guard.cache_set(key, value);
                }
            }
        }
    }
    
    pub fn remove(&self, key: &str) -> Option<EncryptionKey> {
        match self {
            CacheWrapper::TimedCache(cache) => {
                let mut guard = cache.lock().ok()?;
                guard.cache_remove(&key.to_string())
            }
            CacheWrapper::UnboundCache(cache) => {
                let mut guard = cache.lock().ok()?;
                guard.cache_remove(&key.to_string())
            }
            CacheWrapper::RedisCache(cache) => {
                let guard = cache.lock().ok()?;
                match guard.cache_remove(&key.to_string()) {
                    Ok(value) => value,
                    Err(_) => None,
                }
            }
        }
    }
}

/// Get the managed cache from Rocket state
/// Returns a cache wrapper that can handle different cache types
#[doc(hidden)]
pub fn get_cache(req: &Request<'_>) -> Result<CacheWrapper, anyhow::Error> {
    // Try cached::TimedCache
    if let Some(cache) = req.rocket().state::<Arc<Mutex<cached::TimedCache<String, EncryptionKey>>>>() {
        return Ok(CacheWrapper::TimedCache(cache.clone()));
    }
    
    // Try cached::UnboundCache
    if let Some(cache) = req.rocket().state::<Arc<Mutex<cached::UnboundCache<String, EncryptionKey>>>>() {
        return Ok(CacheWrapper::UnboundCache(cache.clone()));
    }

    // Try cached::RedisCache
    if let Some(cache) = req.rocket().state::<Arc<Mutex<cached::RedisCache<String, EncryptionKey>>>>() {
        return Ok(CacheWrapper::RedisCache(cache.clone()));
    }

    Err(anyhow::anyhow!(
        "No supported cache found in rocket state. Make sure to add your cache as managed state with .manage(Arc::new(Mutex::new(your_cache)))"
    ))
}
