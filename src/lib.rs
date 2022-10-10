const VERSION_2_HEADER: &str = "DE259002";
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
pub mod util;
pub use util::randombytes_buf;

/*
#[cfg(feature = "reqwest")]
mod reqwest;
#[cfg(feature = "reqwest")]
pub use reqwest::*;
*/
#[cfg(feature = "rocket")]
pub mod rocket;