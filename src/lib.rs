#![doc(include_str = "../README.md")]

/// Ncryptf version 2 magic header
const VERSION_2_HEADER: &str = "DE259002";
const NCRYPTF_CURRENT_VERSION: i8 = 2;
mod token;
pub use token::Token;
mod keypair;
pub use keypair::Keypair;
mod request;
pub use request::Request;
mod response;
pub use response::Response;
mod error;
pub use error::NcryptfError;
mod authorization;
pub use authorization::Authorization;
mod signature;
pub use signature::Signature;
mod util;
pub use util::randombytes_buf;

#[cfg(feature = "rocket")]
pub mod rocket;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "rocket")]
pub extern crate rocket as rocketfw;

#[cfg(feature = "rocket")]
pub extern crate rocket_db_pools;

#[cfg(feature = "rocket")]
pub use rocket_db_pools::*;

#[cfg(feature = "rocket")]
pub extern crate rocket_dyn_templates;
#[cfg(feature = "rocket")]
pub use rocket_dyn_templates::*;

#[cfg(feature = "sea-orm")]
pub extern crate sea_orm;
#[cfg(feature = "sea-orm")]
pub use sea_orm::*;

#[cfg(feature = "sea-orm")]
pub extern crate sea_orm_migration;

#[cfg(feature = "sea-orm")]
pub use sea_orm_migration::*;

#[cfg(all(feature = "sea-orm", feature = "rocket"))]
pub extern crate sea_orm_rocket;

#[cfg(all(feature = "sea-orm", feature = "rocket"))]
pub use sea_orm_rocket::*;
