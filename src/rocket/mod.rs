use crate::rocket::json::Error as Error;
use std::io;

/// The Ncryptf JSON content type
pub const NCRYPTF_CONTENT_TYPE: &str = "application/vnd.ncryptf+json";

/// The amount of time (in either direction) a request time may differ by and still be accepted.
pub const NCRYPTF_DRIFT_ALLOWANCE: i32 = 90;

/// The cached public key from the request
pub struct RequestPublicKey(pub Vec<u8>);

/// The cached signing public key from the request
pub struct RequestSigningPublicKey(pub Vec<u8>);

mod json;
pub use json::Json;
pub use json::JsonResponse;
mod ek;
pub use ek::EncryptionKey;
pub use ek::ExportableEncryptionKeyData;
pub use ek::*;
mod fairing;
pub use fairing::Fairing;
pub use fairing::FairingConsumed;
pub use fairing::NcryptfRequestVersion;
pub use fairing::NcryptfRawBody;
use rocket::Request;
mod auth;
pub use auth::AuthorizationTrait;
pub use auth::*;
pub use auth::TokenError;

use rocket_db_pools::deadpool_redis::redis;

#[doc(hidden)]
pub(crate) fn get_cache<'r>(req: &'r Request<'_>) -> Result<redis::Connection, Error<'r>> {
    // Retrieve the redis connection string from the figment
    let rdb = match req.rocket().figment().find_value("databases.cache") {
       Ok(config) => {
           let url = config.find("url");
           if url.is_some() {
               let o = url.to_owned().unwrap();
               o.into_string().unwrap()
           } else {
               return Err(Error::Io(io::Error::new(io::ErrorKind::Other, "Unable to retrieve Redis faring configuration.")));
           }
       },
       Err(error) => {
           return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
       }
   };

   // Create a new client
   let client = match redis::Client::open(rdb) {
       Ok(client) => client,
       Err(error) => {
           return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
       }
   };

   // Retrieve the connection string
   match client.get_connection() {
       Ok(conn) => return Ok(conn),
       Err(error) => {
           return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
       }
   };
}