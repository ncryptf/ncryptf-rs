use std::{io, fmt, error};

use rocket::{
    response::{
        Response,
        Responder,
        content,
        self
    },
    Request, http::{
        ContentType,
        Status
    },
    Data,
    data::{
        Limits,
        FromData,
        Outcome
    },
    request::local_cache
};
use serde::{Serialize, Deserialize};
use super::{NCRYPTF_CONTENT_TYPE, EncryptionKey};

use redis::Commands;

// Error returned by the [`Json`] guard when JSON deserialization fails.
#[derive(Debug)]
pub enum Error<'a> {
    /// An I/O error occurred while reading the incoming request data.
    Io(io::Error),
    /// Parser failure
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

///! ncryptf::rocket::Json represents a application/vnd.ncryptf+json, JSON string
///! The JSON struct supports both serialization and de-serialization to reduce implementation time
///!
///! Usage:
///!    Encryption keys and identifiers are stored in Redis. Make sure you have a `rocket_db_pool::Config` setup
///!    for Redis, and added to your rocket figment()
///!    ```rust
///!    .merge(("databases.cache", rocket_db_pools::Config {
///!            url: format!("redis://127.0.0.1:6379/"),
///!            min_connections: None,
///!            max_connections: 1024,
///!            connect_timeout: 3,
///!            idle_timeout: None,
///!        }))
///!    ````
///!
///!    Next, create a struct to represent the request data. This struct _must_ implement Serialize if you want to return a ncryptf encrypted response
///!    ```rust
///!     use rocket::serde::{Serialize, json::Json};
///!
///!     [derive(Serialize)]
///!     #[serde(crate = "rocket::serde")]
///!     struct TestStruct<'r> {
///!         pub hello: &'r str
///!     }
///!    ```
///!
///!   Your request can now be parsed using data tags
///!    ```rust
///!        #[post("/echo", data="<data>")]
///!        fn echo(data: ncryptf::rocket::Json<TestStruct>) {
///!            // data.0 is your TestStruct
///!        }
///!    ```
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
            Err(error) => return Err(Error::Io(error)),
        };


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
        let mut conn: redis::Connection = match client.get_connection() {
            Ok(conn) => conn,
            Err(error) => {
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
            }
        };

        let data = base64::decode(string).unwrap();
        let hash_id = match req.headers().get_one("X-HashId") {
            Some(h) => h,
            None => {
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other, "Encryption key not found.")));
            }
        };

        // Retrieve the encryption key
        let json: String = match conn.get(hash_id) {
            Ok(k) => k,
            Err(error) => {
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
            }
        };

        let ek: EncryptionKey = match serde_json::from_str(&json) {
            Ok(ek) => ek,
            Err(error) => {
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
            }
        };

        let pk = ek.get_box_kp().get_public_key();
        let sk = ek.get_box_kp().get_secret_key();

        // Delete the key if it is ephemeral
        if ek.is_ephemeral() {
            match conn.del(hash_id) {
                Ok(k) => k,
                Err(error) => {
                    return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
                }
            };
        }

        // Decrypt the response, then deserialize the underlying JSON into the requested struct
        match crate::Response::from(sk) {
            Ok(response) => {
                match response.decrypt(
                    data.clone(),
                    Some(pk),
                     None // todo!() this only supports v2 requests
                ) {
                    Ok(msg) => {
                       return Self::from_str(local_cache!(req, msg));
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
