use crate::{Keypair, Signature};
use base64::{engine::general_purpose, Engine as _};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

/// Reusable encryption key data for client parsing
///
/// This is exported for use in your application for deserializing the request.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExportableEncryptionKeyData {
    pub public: String,
    pub signature: String,
    pub hash_id: String,
    pub expires_at: i64,
    pub ephemeral: bool,
}

impl ExportableEncryptionKeyData {
    /// Returns true if this key is expired
    pub fn is_expired(&self) -> bool {
        return chrono::Utc::now().timestamp() >= self.expires_at;
    }

    /// Returns the public key as a Vec
    pub fn get_public_key(&self) -> Option<Vec<u8>> {
        if self.public.is_empty() {
            return None;
        }

        return Some(general_purpose::STANDARD.decode(self.public.clone()).unwrap());
    }

    /// Returns the signature key as a Vec
    pub fn get_signature_key(&self) -> Option<Vec<u8>> {
        if self.public.is_empty() {
            return None;
        }

        return Some(general_purpose::STANDARD.decode(self.signature.clone()).unwrap());
    }
}

/// Represents an Encryption key used to encrypt and decrypt requests
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionKey {
    bkp: Keypair,
    skp: Keypair,
    ephemeral: bool,
    pub expires_at: i64,
    hash_id: String,
}

impl EncryptionKey {
    /// Returns the box keypair
    pub fn get_box_kp(&self) -> Keypair {
        return self.bkp.clone();
    }

    /// Returns the signing keypair
    pub fn get_sign_kp(&self) -> Keypair {
        return self.skp.clone();
    }

    /// Returns true if the key is meant to be used only once
    pub fn is_ephemeral(&self) -> bool {
        return self.ephemeral;
    }

    /// Returns the hash id
    pub fn get_hash_id(&self) -> String {
        return self.hash_id.clone();
    }

    /// Returns true if the token is expired
    /// Expiration should be handled server side
    /// But the client should know if they need a new key
    pub fn is_expired(&self) -> bool {
        if chrono::Utc::now().timestamp() >= self.expires_at {
            return true;
        }

        return false;
    }

    /// Creates a new struct with an ephemeral flag set
    pub fn new(ephemeral: bool) -> Self {
        let s: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        // Encryption keys are valid for an hour
        let expiration = chrono::Utc::now() + chrono::Duration::hours(1);
        return Self {
            bkp: Keypair::new(),
            skp: Signature::new(),
            ephemeral: ephemeral,
            expires_at: expiration.timestamp(),
            hash_id: s,
        };
    }
}

/// EkRoute provides a generic route which you can use to generate ephemeral (single use) encryption keys to bootstrap your request/response cycle within your application.
///
/// ### Setup
///  1. Create a cache using one of the supported cache types:
///
///      ```rust
///      use cached::{TimedCache, UnboundCache};
///      use std::sync::{Arc, Mutex};
///      use ncryptf::rocket::{EncryptionKey, CacheWrapper};
///
///      // TimedCache with 1 hour expiration
///      let timed_cache = Arc::new(Mutex::new(TimedCache::with_lifespan(3600)));
///      let cache_wrapper = CacheWrapper::TimedCache(timed_cache);
///      
///      // Or UnboundCache (no automatic expiration)
///      let unbound_cache = Arc::new(Mutex::new(UnboundCache::new()));
///      let cache_wrapper = CacheWrapper::UnboundCache(unbound_cache);
///
///      // Or RedisCache (requires redis feature)
///      let redis_cache = Arc::new(Mutex::new(
///          cached::RedisCache::new("redis://127.0.0.1/", std::time::Duration::from_secs(3600))
///              .build().unwrap()
///      ));
///      let cache_wrapper = CacheWrapper::RedisCache(redis_cache);
///      ```
///
///  2. Add the CacheWrapper as managed state to your Rocket instance:
///
///      ```rust
///      let rocket = rocket::build()
///          .manage(cache_wrapper)
///          .mount("/ncryptf", routes![ncryptf_ek_route]);
///      ```
///
///  3. Call the setup macro to instantiate the route:
///
///      ```rust
///      ncryptf::ek_route!();
///      ```
///
///  4. Mount the route `ncryptf_ek_route` exposed by the macro.
///
/// ### Features
/// - **Unified Cache Interface**: Works with TimedCache, UnboundCache, and RedisCache through CacheWrapper
/// - **Automatic Cache Management**: No need to manually handle different cache types
/// - **Simple Integration**: Just manage a single CacheWrapper state instead of multiple cache types
/// - **Parameterless Macro**: No arguments needed - the macro detects the managed cache automatically
///
/// Note: The CacheWrapper abstracts over all supported cache types: `TimedCache<String, EncryptionKey>`, `UnboundCache<String, EncryptionKey>`, and `RedisCache<String, EncryptionKey>`
#[macro_export]
macro_rules! ek_route {
    () => {
        use rocket::{get, http::Status, State};
        use ncryptf::rocket::{EncryptionKey, ExportableEncryptionKeyData, CacheWrapper};
        use base64::{Engine as _, engine::general_purpose};

        #[get("/ek")]
        pub async fn ncryptf_ek_route(
            cache: &State<CacheWrapper>,
        ) -> Result<ncryptf::rocket::Json<ExportableEncryptionKeyData>, Status> {
            let ek = EncryptionKey::new(true);
            
            // Store the encryption key in the cache
            cache.set(ek.get_hash_id(), ek.clone());

            return Ok(ncryptf::rocket::Json(ExportableEncryptionKeyData {
                public: general_purpose::STANDARD.encode(ek.get_box_kp().get_public_key()),
                signature: general_purpose::STANDARD.encode(ek.get_sign_kp().get_public_key()),
                hash_id: ek.get_hash_id(),
                ephemeral: true,
                expires_at: ek.expires_at,
            }));
        }
    };
}
