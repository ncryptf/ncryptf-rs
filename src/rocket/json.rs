use std::{io, fmt, error};

use rocket::{response::{Response, Responder, content, self}, Request, http::{ContentType, Status}, Data, data::{Limits, FromData}, data::{Outcome, self}, request::{FromRequest, self}, State};
use rocket::request::local_cache;
use serde::{Serialize, Deserialize, Serializer};
use super::NCRYPTF_CONTENT_TYPE;

// Error returned by the [`Json`] guard when JSON deserialization fails.
#[derive(Debug)]
pub enum Error<'a> {
    /// An I/O error occurred while reading the incoming request data.
    Io(io::Error),

    /// The client's data was received successfully but failed to parse as valid
    /// JSON or as the requested type. The `&str` value in `.0` is the raw data
    /// received from the user, while the `Error` in `.1` is the deserialization
    /// error from `serde`.
    Parse(&'a str, serde_json::error::Error),
}

impl<'a> fmt::Display for Error<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "i/o error: {}", err),
            Self::Parse(_, err) => write!(f, "parse error: {}", err),
        }
    }
}

impl<'a> error::Error for Error<'a> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Parse(_, err) => Some(err),
        }
    }
}

/// Representation for an ncryptf encrypted JSON object
#[derive(Debug, Clone)]
pub struct Json<T>(pub T);

impl<T> Json<T> {
    /// Returns the underlying serde_json::Value object
    pub fn into_inner(self) -> T {
        return self.0;
    }

    /// Returns a serde_json::Value wrapped as an ncryptf::Json representation
    pub fn from_value(value: T) -> Self {
        return Self(value);
    }
}

impl<'r, T: Deserialize<'r>> Json<T> {
    fn from_str(s: &'r str) -> Result<Self, Error<'r>> {
        serde_json::from_str(s).map(Json).map_err(|e| Error::Parse(s, e))
    }

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Result<Self, Error<'r>> {
        let limit = req.limits().get("json").unwrap_or(Limits::JSON);
        let string = match data.open(limit).into_string().await {
            Ok(s) if s.is_complete() => s.into_inner(),
            Ok(_) => {
                let eof = io::ErrorKind::UnexpectedEof;
                return Err(Error::Io(io::Error::new(eof, "data limit exceeded")));
            },
            Err(e) => return Err(Error::Io(e)),
        };

        // How do we access Redis, or a generic cache instance from here?
        // Config can be found here:
        // let config = req.rocket().figment().find_value("databases.cache");
        // But how can we access the original connection pool if the underlying struct is undefined in the library?
        // Force redis then re-initialize a connection?
        // Use stretto::AsyncCache::new(12960, 1e6 as i64, tokio::spawn).unwrap() ?
        // How do we persist AnyCache?
        let pk = req.headers().get_one("X-Pubkey").unwrap();
        let sig_pk = req.headers().get_one("X-Sig-Pubkey").unwrap();
        let sk= req.headers().get_one("X-Seckey").unwrap();
        let sig_sk = req.headers().get_one("X-Sig-Seckey").unwrap();

        match crate::Response::from(
            base64::decode(sk).unwrap()
        ) {
            Ok(response) => {
                match response.decrypt(
                    base64::decode(string).unwrap(),
                    Some(base64::decode(pk).unwrap()),
                     None
                ) {
                    Ok(msg) => {
                       return  Self::from_str(local_cache!(req, msg));
                    },
                    Err(error) =>{
                        return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
                    }
                };
            },
            Err(error) =>{
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
            }
        };

    }
}

#[rocket::async_trait]
impl<'r, T: Deserialize<'r>> FromData<'r> for Json<T> {
    type Error = Error<'r>;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        match Self::from_data(req, data).await {
            Ok(value) => Outcome::Success(value),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                Outcome::Failure((Status::PayloadTooLarge, Error::Io(e)))
            },
            Err(Error::Parse(s, e)) if e.classify() == serde_json::error::Category::Data => {
                Outcome::Failure((Status::UnprocessableEntity, Error::Parse(s, e)))
            },
            Err(e) => Outcome::Failure((Status::BadRequest, e)),

        }
    }
}

///! Allows for ncryptf::rocket::Json to be emitted as a responder to reduce code overhead
///! This responder will handle encrypting the underlying request data correctly for all supported
///! ncryptf version.
///!
///! Usage:
///!
///! ```rust
///! use ncryptf::rocket::Json;
///!
///! #[get("/")]
///! fn out() -> ncryptf::rocket::Json {
///!    ncryptf::rocket::Json::from_str(r#"{ "Hello": "World!" }"#).unwrap()
///! }
///! ```
impl<'r, T: Serialize> Responder<'r, 'static> for Json<T> {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        match req.headers().get_one("Accept") {
            Some(accept) => {
                match accept {
                    NCRYPTF_CONTENT_TYPE => {
                        let message = "test".to_string();

                        // How to get attributes from request??

                        Response::build_from(message.respond_to(req)?)
                            .header(ContentType::new("application", "vnd.ncryptf+json"))
                            .ok()
                    },
                    _ => {
                        // Default to a JSON response if the content type is not an ncryptf content type
                        // This is compatible with other implementations
                        content::RawJson("").respond_to(req)
                    }
                }
            },
            None => {
                // If an Accept is not defined on the request, return JSON when this struct is requested
                content::RawJson("").respond_to(req)
            }
        }
    }
}
