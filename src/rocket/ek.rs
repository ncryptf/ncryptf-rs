
use serde::{Deserialize, Serialize};
use crate::Keypair;
use crate::Signature;
use rand::{distributions::Alphanumeric, Rng};

#[derive(Serialize, Deserialize)]
pub struct ExportableEncryptionKeyData {
    pub public: String,
    pub signature: String,
    pub hash_id: String
}

/// Represents an Encryption key used to encrypt and decrypt requests
#[derive(Serialize, Deserialize)]
pub struct EncryptionKey {
    bkp: Keypair,
    skp: Keypair,
    ephemeral: bool,
    pub expires_at: i64,
    hash_id: String
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
        if self.expires_at.clone() > chrono::Utc::now().timestamp() {
            return true;
        }

        return false;
    }

    /// Creates a new struct with an ephemeral flag set
    pub fn new(ephemeral: bool) -> Self {
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        return Self {
            bkp: Keypair::new(),
            skp: Signature::new(),
            ephemeral: ephemeral,
            expires_at: chrono::Utc::now().timestamp() + 3600,
            hash_id: s
        }
    }
}

///! EkRoute provides a generic route which you can use to generate ephemeral (single use) encryption keys to bootstrap your request/response cycle within your application.
///!
///! Setup:
///!     1. Ncryptf utilizes Redis as a shared backend cache. You must have a functional Redis server available to utilize this functionality.
///!     2. Create a rocket_db_pool for Redis with the `cache` Database name.
///!
///!         ```rust
///!         use rocket_db_pools::{Database, deadpool_redis};
///!
///!         #[derive(Database)]
///!         #[database("cache")]
///!         pub struct RedisDb(deadpool_redis::Pool);
///!         ```
///!
///!     3. Add a Redis DB Pool figment to your Rocket build configuration:
///!
///!         ```rust
///!         let config = rocket::Config::figment()
///!             [... other configurations here...]
///!             .merge(("databases.cache", rocket_db_pools::Config {
///!                 url: format!("redis://127.0.0.1:6379/"),
///!                 min_connections: None,
///!                 max_connections: 1024,
///!                 connect_timeout: 3,
///!                 idle_timeout: None,
///!             }));
///!         ```
///!
///!     4. Attach the figment to your rocket instance:
///!
///!         ```rust
///!         let rocket = rocket::custom(config).attach(RedisDb::init());
///!         ```
///!
///!     5. Call the setup macro to instantiate the route:
///!
///!     ```rust
///!     ncryptf::ek_route!(RedisDb);
///!     ```
///!
///!     6. Mount the route `ncryptf_ek_route` exposed by the macro. The following mount will make the route available at`/ncryptf/ek`
///!
///!     ```rust
///!     rocket .mount("/ncryptf", routes![ncryptf_ek_route]);
///!     ```
#[macro_export]
macro_rules! ek_route {
    ($T: ty) => {
            use rocket::get;
            use rocket::http::Status;
            use rocket_db_pools::Database;
            use rocket_db_pools::Connection as RedisConnection;
            #[allow(unused_imports)] // for rust-analyzer
            use rocket_db_pools::deadpool_redis::redis::AsyncCommands;

            use serde::{Deserialize, Serialize};
            use ncryptf::rocket::{EncryptionKey, ExportableEncryptionKeyData};

            #[get("/ek")]
            pub async fn ncryptf_ek_route( rdb: RedisConnection<$T>) -> Result<ncryptf::rocket::Json<ExportableEncryptionKeyData>, Status> {
                let ek = EncryptionKey::new(true);
                let mut redis: rocket_db_pools::deadpool_redis::Connection = rdb.into_inner();

                let _result = match redis.set_ex(
                    ek.get_hash_id(),
                    serde_json::to_string(&ek).unwrap(),
                    3600
                ).await {
                    Ok(result) => result,
                    Err(_) => return Err(Status::InternalServerError)
                };

                return Ok(ncryptf::rocket::Json(ExportableEncryptionKeyData {
                    public: base64::encode(ek.get_box_kp().get_public_key()),
                    signature: base64::encode(ek.get_sign_kp().get_public_key()),
                    hash_id: ek.get_hash_id()
                }));
            }
        }
    }