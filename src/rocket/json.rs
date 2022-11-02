use std::{error, fmt, io};

use super::{
    fairing::FairingConsumed, get_cache, EncryptionKey, RequestPublicKey, RequestSigningPublicKey,
    NCRYPTF_CONTENT_TYPE,
};
use anyhow::anyhow;
use rocket::{
    data::{FromData, Limits, Outcome},
    http::{ContentType, Header, Status},
    response::{self, Responder, Response},
    Data, Request,
};
use serde::{Deserialize, Serialize};

#[allow(unused_imports)] // for rust-analyzer
use rocket_db_pools::deadpool_redis::redis::Commands;

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

/// ncryptf::rocket::Json represents a application/vnd.ncryptf+json, JSON string
/// The JSON struct supports both serialization and de-serialization to reduce implementation time within your application
///
/// ### Usage
/// Encryption keys and identifiers are stored in Redis. Make sure you have a `rocket_db_pool::Config` setup
/// for Redis, and added to your rocket figment()
/// You do not have to setup a RequestGuard for Redis, this just uses the same configuration
/// ```rust
/// .merge(("databases.cache", rocket_db_pools::Config {
///         url: format!("redis://127.0.0.1:6379/"),
///         min_connections: None,
///         max_connections: 1024,
///         connect_timeout: 3,
///         idle_timeout: None,
///     }))
/// ````
///
/// Next, create a struct to represent the request data. This struct MUST implement Serialize if you want to return a ncryptf encrypted response
/// ```rust
///  use rocket::serde::{Serialize, json::Json};
///
///  [derive(Serialize)]
///  #[serde(crate = "rocket::serde")]
///  struct TestStruct<'r> {
///      pub hello: &'r str
///  }
/// ```
///
/// our request can now be parsed using data tags.
/// Responses can be automatically converted into an JSON encrypted ncryptf response by returning `ncryptf::rocket::Json<T>`
///
///  If your header is application/vnd.ncryptf+json, returning a ncryptf::rocket::Json<T> will return an encrypted response
///  If the header is an application/json (or anything else), ncryptf::rocket::Json<T> will return a rocket::serde::json::Json<T> equivalent JSON response in plain text
///
/// ```rust
///     #[post("/echo", data="<data>")]
///     fn echo(data: ncryptf::rocket::Json<TestStruct>) -> ncryptf::rocket::Json<TestStruct> {
///         // data.0 is your TestStruct
///         //
///         return ncryptf::rocket::Json(data.0);
///     }
/// ```
///
///
/// nryptf::rocket::Json<T>` supercedes rocket::serde::json::Json<T> for both encrypted messages, and regular JSON. If you intend to use
///  the `Authorization` trait to authenticate users, you MUST receive and return this for your data type
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

    /// Deserializes the request sting into a raw JSON string
    pub fn deserialize_req_from_string<'r>(
        req: &'r Request<'_>,
        string: String,
    ) -> Result<String, Error<'r>> {
        match req.headers().get_one("Content-Type") {
            Some(h) => {
                match h {
                    NCRYPTF_CONTENT_TYPE => {
                        // Retrieve the redis connection
                        let mut conn: rocket_db_pools::deadpool_redis::redis::Connection =
                            match get_cache(req) {
                                Ok(conn) => conn,
                                Err(error) => return Err(error),
                            };

                        // Convert the base64 payload into Vec<u8>
                        let data = base64::decode(string).unwrap();

                        // Retrieve the HashID header
                        let hash_id = match req.headers().get_one("X-HashId") {
                            Some(h) => h,
                            None => {
                                return Err(Error::Io(io::Error::new(
                                    io::ErrorKind::Other,
                                    "Missing client provided hash identifier.",
                                )));
                            }
                        };

                        // Retrive the JSON struct for the encryption key
                        let json = match conn.get(hash_id) {
                            Ok(k) => k,
                            Err(_error) => "".to_string(),
                        };

                        if json.is_empty() {
                            return Err(Error::Io(io::Error::new(
                                io::ErrorKind::Other,
                                "Encryption key is either invalid, or may have expired.",
                            )));
                        }

                        // Deserialize the encryption key into a useful struct
                        let ek: EncryptionKey = match serde_json::from_str(&json) {
                            Ok(ek) => ek,
                            Err(_error) => {
                                return Err(Error::Io(io::Error::new(
                                    io::ErrorKind::Other,
                                    "Encryption key is either invalid, or may have expired.",
                                )));
                            }
                        };

                        // Retrieve the secret key
                        let sk = ek.get_box_kp().get_secret_key();

                        // Delete the key if it is ephemeral
                        if ek.is_ephemeral() {
                            match conn.del(hash_id) {
                                Ok(k) => k,
                                Err(_) => {}
                            };
                        }

                        // Decrypt the response, then deserialize the underlying JSON into the requested struct
                        match crate::Response::from(sk) {
                            Ok(response) => {
                                // Pull the public key from the response then store it in the local cache so we can re-use it later
                                // We need this in order to send an encrypted response back since Responder::respond_to
                                // won't let us read the request
                                match crate::Response::get_public_key_from_response(data.clone()) {
                                    Ok(cpk) => {
                                        req.local_cache(|| {
                                            return RequestPublicKey(cpk.clone());
                                        });
                                    }
                                    Err(error) => {
                                        return Err(Error::Io(io::Error::new(
                                            io::ErrorKind::Other,
                                            error.to_string(),
                                        )));
                                    }
                                };

                                // Extract the signature key
                                match crate::Response::get_signing_public_key_from_response(
                                    data.clone(),
                                ) {
                                    Ok(cpk) => {
                                        req.local_cache(|| {
                                            return RequestSigningPublicKey(cpk.clone());
                                        });
                                    }
                                    Err(error) => {
                                        return Err(Error::Io(io::Error::new(
                                            io::ErrorKind::Other,
                                            error.to_string(),
                                        )));
                                    }
                                };

                                // Pull the public key and nonce from the headers if they are set.
                                // If they are set they assume priority, and response.decrypt will likely decrypt this as a V1 response
                                let public_key = match req.headers().get_one("X-PubKey") {
                                    Some(h) => Some(h.as_bytes().to_vec()),
                                    None => None,
                                };

                                let nonce = match req.headers().get_one("X-Nonce") {
                                    Some(h) => Some(h.as_bytes().to_vec()),
                                    None => None,
                                };

                                // Decrypt the request
                                match response.decrypt(data.clone(), public_key, nonce) {
                                    Ok(msg) => {
                                        // Serialize this into a struct, and store the decrypted response in the cache
                                        // We'll need this for the Authorization header
                                        return Ok(req.local_cache(|| return msg).to_owned());
                                    }
                                    Err(error) => {
                                        return Err(Error::Io(io::Error::new(
                                            io::ErrorKind::Other,
                                            error.to_string(),
                                        )));
                                    }
                                };
                            }
                            Err(error) => {
                                return Err(Error::Io(io::Error::new(
                                    io::ErrorKind::Other,
                                    error.to_string(),
                                )));
                            }
                        };
                    }
                    // If this is a json request, return raw json
                    "json" => {
                        return Ok(req.local_cache(|| return string).to_owned());
                    }
                    // For now, return JSON even if another header was sent.
                    _ => {
                        return Ok(req.local_cache(|| return string).to_owned());
                    }
                }
            }
            // If there isn't an Accept header, also return JSON
            None => {
                return Ok(req.local_cache(|| return string).to_owned());
            }
        };
    }
}

impl<'r, T: Deserialize<'r>> Json<T> {
    fn from_str(s: &'r str) -> Result<Self, Error<'r>> {
        return serde_json::from_str(s)
            .map(Json)
            .map_err(|e| Error::Parse(s, e));
    }

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Result<Self, Error<'r>> {
        let is_consumed = req.local_cache(|| FairingConsumed(false));
        match is_consumed.0 {
            // If the fairing is attached and we have already decrypted the string, we can simply return it as is without needing to decrypt it a second time
            true => return Self::from_str(req.local_cache(|| return "".to_string())),
            false => {
                let limit = req.limits().get("json").unwrap_or(Limits::JSON);
                let string = match data.open(limit).into_string().await {
                    Ok(s) if s.is_complete() => s.into_inner(),
                    Ok(_) => {
                        let eof = io::ErrorKind::UnexpectedEof;
                        return Err(Error::Io(io::Error::new(eof, "data limit exceeded")));
                    }
                    Err(error) => return Err(Error::Io(error)),
                };

                match Self::deserialize_req_from_string(req, string) {
                    Ok(s) => {
                        return Self::from_str(req.local_cache(|| return s));
                    }
                    Err(error) => return Err(error),
                };
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
            }
            Err(Error::Parse(s, e)) if e.classify() == serde_json::error::Category::Data => {
                let sttr = req.local_cache(|| return "".to_string());
                dbg!(sttr);
                dbg!(e.to_string());
                Outcome::Failure((Status::UnprocessableEntity, Error::Parse(s, e)))
            }
            Err(e) => Outcome::Failure((Status::BadRequest, e)),
        }
    }
}

/// Allows for ncryptf::rocket::Json to be emitted as a responder to reduce code overhead
/// This responder will handle encrypting the underlying request data correctly for all supported
/// ncryptf versionn
impl<'r, T: Serialize> Responder<'r, 'static> for Json<T> {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        match respond_to_with_ncryptf(self, Status::Ok, req) {
            Ok(response) => response,
            Err(_) => return Err(Status::InternalServerError),
        }
    }
}

/// ncryptf::rocket::JsonResponse is identical to ncryptf::rocket::Json<T> except that is also supports setting
/// a status code on the response.
///
/// You may find this useful for:
///     - Returning an common JSON structure for parsing in another clients / application
///     - Returning an error struct if your request is not successful to inform the client on steps they can
///        perform to resolve the error
///
/// The response with JsonResponse<T> will be identical to Json<T>. See Json<T> for more information
#[derive(Debug, Clone)]
pub struct JsonResponse<T> {
    pub status: Status,
    pub json: Json<T>,
}

impl<'r, T: Serialize> Responder<'r, 'static> for JsonResponse<T> {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        return match respond_to_with_ncryptf(self.json, self.status, req) {
            Ok(response) => response,
            Err(_) => return Err(Status::InternalServerError),
        };
    }
}

pub fn respond_to_with_ncryptf<'r, 'a, T: serde::Serialize>(
    m: Json<T>,
    status: Status,
    req: &'r Request<'_>,
) -> Result<response::Result<'static>, anyhow::Error> {
    // Handle serialization
    let message = match serde_json::to_string(&m.0) {
        Ok(json) => json,
        Err(_error) => return Err(anyhow!("Could not deserialize message")),
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
                            // If the header isn't sent, then we have no way to encrypt a response the client can use
                            None =>return Err(anyhow!("Public key is not available on request. Unable to re-encrypt message to client."))
                        };
                    } else {
                        pk = cpk.0.clone();
                    }

                    let ek = EncryptionKey::new(false);
                    let d = serde_json::to_string(&ek).unwrap();

                    // Create an encryption key then store it in Redis
                    // The client can choose to use the new key or ignore it, but we're always going to provide our own for each request
                    let mut conn: rocket_db_pools::deadpool_redis::redis::Connection =
                        match get_cache(req) {
                            Ok(conn) => conn,
                            Err(_error) => return Err(anyhow!("Unable to connect to Redis.")),
                        };

                    match conn.set_ex(ek.get_hash_id(), d, 3600) {
                        Ok(r) => r,
                        Err(_) => {}
                    };

                    let mut request = match crate::Request::from(
                        ek.get_box_kp().get_secret_key(),
                        // todo!() we should pull out the token signature, if it is set and use it
                        ek.get_sign_kp().get_secret_key(),
                    ) {
                        Ok(request) => request,
                        Err(_error) => return Err(anyhow!("Unable to encrypt message")),
                    };

                    let content = match request.encrypt(message, pk) {
                        Ok(content) => content,
                        Err(_error) => return Err(anyhow!("Unable to encrypt message")),
                    };

                    let d = base64::encode(content);

                    let respond_to = match d.respond_to(req) {
                        Ok(s) => s,
                        Err(_) => return Err(anyhow!("Could not send response")),
                    };

                    return Ok(Response::build_from(respond_to)
                        .header(ContentType::new("application", "vnd.ncryptf+json"))
                        .header(Header::new(
                            "x-public-key",
                            base64::encode(ek.get_box_kp().get_public_key()),
                        ))
                        .header(Header::new(
                            "x-signature-public-key",
                            base64::encode(ek.get_sign_kp().get_public_key()),
                        ))
                        .header(Header::new(
                            "x-public-key-expiration",
                            ek.expires_at.to_string(),
                        ))
                        .header(Header::new("x-hashid", ek.get_hash_id()))
                        .status(status)
                        .ok());
                }
                _ => {
                    let respond_to = match message.respond_to(req) {
                        Ok(s) => s,
                        Err(_) => return Err(anyhow!("Could not send response")),
                    };
                    // Default to a JSON response if the content type is not an ncryptf content type
                    // This is compatible with other implementations of ncryptf
                    return Ok(Response::build_from(respond_to)
                        .header(ContentType::new("application", "json"))
                        .status(status)
                        .ok());
                }
            }
        }
        None => {
            let respond_to = match message.respond_to(req) {
                Ok(s) => s,
                Err(_) => return Err(anyhow!("Could not send response")),
            };

            // If an Accept is not defined on the request, return JSON when this struct is requested
            return Ok(Response::build_from(respond_to)
                .header(ContentType::new("application", "json"))
                .status(status)
                .ok());
        }
    }
}
