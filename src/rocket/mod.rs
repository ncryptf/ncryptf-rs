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

use rocket_db_pools::{
    deadpool_redis::{
        Config,
        Connection,
        Runtime
    }
};

use async_std::task;

#[allow(unused_imports)] // for rust-analyzer
use rocket_db_pools::deadpool_redis::redis::AsyncCommands;

#[doc(hidden)]
pub(crate) fn get_cache<'r>(req: &'r Request<'_>) -> Result<Connection, Error<'r>> {
    match req.rocket().figment().find_value("databases.cache") {
        Ok(config) => match config.find("url") {
            Some(url) => {
                let cfg = Config::from_url(url.into_string().unwrap());
                let pool = cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
                match  task::block_on(async {
                    return pool.get().await;
                }) {
                    Ok(conn) => return Ok(conn),
                    Err(error) => return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())))
                };
            },
            None =>  Err(Error::Io(io::Error::new(io::ErrorKind::Other, "Unable to retrieve cache faring configuration.")))
        },
        Err(error) => return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())))
    }
}