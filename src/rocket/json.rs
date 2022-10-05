use std::{io, fmt, error};

use rocket::{
    response::{
        Response,
        Responder,
        self
    },
    Request, http::{
        ContentType,
        Status, Header
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

#[derive(Debug, Clone)]
pub struct RequestPublicKey(pub Vec<u8>);

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
///! The JSON struct supports both serialization and de-serialization to reduce implementation time within your application
///!
///! Usage:
///!    Encryption keys and identifiers are stored in Redis. Make sure you have a `rocket_db_pool::Config` setup
///!    for Redis, and added to your rocket figment()
///!    You do not have to setup a RequestGuard for Redis, this just uses the same configuration
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
///!    Next, create a struct to represent the request data. This struct MUST implement Serialize if you want to return a ncryptf encrypted response
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
///!   Your request can now be parsed using data tags.
///!    Responses can be automatically converted into an JSON encrypted ncryptf response by returning `ncryptf::rocket::Json<T>`
///!
///!     If your header is application/vnd.ncryptf+json, returning a ncryptf::rocket::Json<T> will return an encrypted response
///!     If the header is an application/json (or anything else), ncryptf::rocket::Json<T> will return a rocket::serde::json::Json<T> equivalent JSON response in plain text
///!
///!    ```rust
///!        #[post("/echo", data="<data>")]
///!        fn echo(data: ncryptf::rocket::Json<TestStruct>) -> ncryptf::rocket::Json<TestStruct> {
///!            // data.0 is your TestStruct
///!            //
///!            return ncryptf::rocket::Json(data.0);
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

/// Retrieves the cache
fn get_cache<'r>(req: &'r Request<'_>) -> Result<redis::Connection, Error<'r>> {
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

        let mut conn: redis::Connection = match get_cache(req) {
            Ok(conn) => conn,
            Err(error) => return Err(error)
        };

        let data = base64::decode(string).unwrap();
        let hash_id = match req.headers().get_one("X-HashId") {
            Some(h) => h,
            None => {
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other, "Missing client provided hash identifier.")));
            }
        };

        let json: String = match conn.get(hash_id) {
            Ok(k) => k,
            Err(_error) => {
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other, "Encryption key is either invalid, or may have expired.")));
            }
        };

        let ek: EncryptionKey = match serde_json::from_str(&json) {
            Ok(ek) => ek,
            Err(_error) => {
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other, "Encryption key is either invalid, or may have expired.")));
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
                match crate::Response::get_public_key_from_response(data.clone()) {
                    Ok(cpk) => {
                        // Store the client public key in the request local cache since we can't read the body later
                        req.local_cache(|| {
                            return RequestPublicKey(cpk.clone());
                        });
                    },
                    Err(error) => {
                        return Err(Error::Io(io::Error::new(io::ErrorKind::Other, error.to_string())));
                    }
                };

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
         // Handle serialization
         let message = match serde_json::to_string(&self.0) {
            Ok(json) => json,
            Err(_error) => {
                return Err(Status::InternalServerError);
            }
        };

        match req.headers().get_one("Accept") {
            Some(accept) => {
                match accept {
                    NCRYPTF_CONTENT_TYPE => {
                        // Retrieve the client public key
                        let cpk = req.local_cache(|| {
                            return RequestPublicKey(Vec::<u8>::new());
                        });

                        let pk: Vec<u8>;
                        // If the cache data is empty, check the header as a fallback
                        if cpk.0.is_empty() {
                            pk = match req.headers().get_one("X-PubKey") {
                                Some(h) => base64::decode(h).unwrap(),
                                None => {
                                    // If the header isn't set the client did something wrong so fail
                                    return Err(Status::BadRequest);
                                }
                            };
                        } else {
                            pk = cpk.0.clone();
                        }

                        // Create an encryption key then store it in Redis
                        // The client can choose to use the new key or ignore it, but we're always going to provide our own for each request
                        let mut conn: redis::Connection = match get_cache(req) {
                            Ok(conn) => conn,
                            Err(_error) => return Err(Status::InternalServerError)
                        };

                        let ek = EncryptionKey::new(false);
                        let d = serde_json::to_string(&ek).unwrap();

                        match conn.set_ex(ek.get_hash_id(), d, 3600) {
                            Ok(r) => r,
                            Err(_) => return Err(Status::InternalServerError)
                        };

                        let mut request = match crate::Request::from(
                            ek.get_box_kp().get_secret_key(),
                            // todo!() we should pull out the token signature, if it is set and use it
                            ek.get_sign_kp().get_secret_key()
                        ) {
                            Ok(request) => request,
                            Err(_error) => return Err(Status::InternalServerError)
                        };

                        let content = match request.encrypt(message, pk) {
                            Ok(content) => content,
                            Err(_error) => return Err(Status::InternalServerError)
                        };

                        let d = base64::encode(content);

                        return Response::build_from(d.respond_to(req)?)
                            .header(ContentType::new("application", "vnd.ncryptf+json"))
                            .header(Header::new("x-public-key-expiration", ek.expires_at.to_string()))
                            .header(Header::new("x-hashid", ek.get_hash_id()))
                            .ok()
                    },
                    _ => {
                        // Default to a JSON response if the content type is not an ncryptf content type
                        // This is compatible with other implementations of ncryptf
                        return Response::build_from(message.respond_to(req)?)
                            .header(ContentType::new("application", "json"))
                            .ok()
                    }
                }
            },
            None => {
                // If an Accept is not defined on the request, return JSON when this struct is requested
                return Response::build_from(message.respond_to(req)?)
                    .header(ContentType::new("application", "json"))
                    .ok()
            }
        }
    }
}
