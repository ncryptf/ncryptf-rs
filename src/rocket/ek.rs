/// EkRoute provides a generic route which you can use to generate ephemeral (single use) encryption keys to bootstrap your request/response cycle within your application.
///
/// ### Setup
///  1. Create a cache using one of the supported cache types:
///
///      ```rust
///      use cached::{TimedCache, UnboundCache};
///      use std::sync::{Arc, Mutex};
///      use ncryptf::shared::{EncryptionKey};
///      use ncryptf::rocket::{CacheWrapper};
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
        use ncryptf::shared::{EncryptionKey, ExportableEncryptionKeyData};
        use ncryptf::rocket::CacheWrapper;
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
