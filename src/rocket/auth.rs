use async_trait::async_trait;

#[derive(Debug)]
pub enum TokenError {
    InvalidToken,
    SignatureInvalid,
    ServerError
}

/// AuthorizationTrait is a trait that should be implemented by your User entity.
/// This trait, in conjunction with the ncryptf::auth!() macro, enables individual
/// Users to be returned as part of a Rocket request guard.
#[async_trait]
pub trait AuthorizationTrait: Sync + Send + 'static {
    /// Returns a ncryptf::Token instance given an access_token. A cache instance is provided to Redis, however you are not obliged to use it
    async fn get_token_from_access_token(access_token: String, cache:  &mut redis::Connection) -> Result<crate::Token, TokenError>;

    /// Returns a <Self> (User) entity given a specific token
    /// You can use this method to determine the appropriate access credentials, scoping, and permissions.
    /// An optional connection to Redis is provided, however you are not obliged to use it.
    async fn get_user_from_token(token: crate::Token, cache: &mut redis::Connection) -> Result<Box<Self>, TokenError>;
}

///! The ncryptf::auth!() macro provides the appropriate generic implementation details of FromRequest to allow User entities to be returned
///! as a Rocket request guard (FromRequest). The core features of ncryptf authorization verification are implemented through this macro.
///! If you wish to utilize ncryptf's authorization features you must perform the following.
///!
///! Usage:
///!     1. Attach the ncryptf::Fairing to your Rocket configuration:
///!
///!     ```rust
///!     let rocket = rocket::custom(config)
///!         .attach(NcryptfFairing);
///!     ```
///!
///!     2. Define your User entity, and have to implement AuthorizationTrait.
///!
///!     3. At the end of your User entity struct file, bind the macro FromRequest to your User entity.
///!
///!     ```rust
///!     ncryptf::auth!(User);
///!     ```
///!
///!     4. Your User is now available as part of the request guard:
///!     ```
///!     #[post("/auth_info", data="<data>")]
///!     fn auth_echo(_user: User){
///!         dbg!(_user);
///!     }
///!     ```
///!
///!     **NOTE**: The Authorization Features of ncryptf are exclusively available if and only if you set the appropriate Content-Type to either application/json, or application/vnd.ncryptf+json, _even for GET requests_,
///!     and other requests that don't have a body. The FromRequest functionality is only available for these content types.
///!
///!     Additionally, ncryptf::rocket::Json will handle all JSON + Ncryptf+JSON content types when this is in use. ncryptf::rocket::Json is mostly compatible with rocket::serde::Json, but shares the same limitations, features,
///!     and particularities.
pub mod auth {
    #[macro_export]
    macro_rules! auth {
        ($T: ty) => {
            use chrono::{Utc};
            use rocket::{
                request::{
                    self,
                    Request,
                    FromRequest
                },
                outcome::Outcome,
                http,
            };
            use ncryptf::rocket::TokenError;
            use ncryptf::rocket::AuthorizationTrait;

            #[rocket::async_trait]
            impl<'r> FromRequest<'r> for $T {
                type Error = TokenError;

                async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {

                    let body = req.local_cache(|| return "".to_string());

                    let mut cache = match ncryptf::rocket::get_cache(req) {
                        Ok(cache) => cache,
                        Err(_error) => return Outcome::Failure((rocket::http::Status::InternalServerError, TokenError::ServerError))
                    };

                    // Retrieve the Authorization header
                    let header: String = match req.headers().get_one("Authorization") {
                        Some(h) => h.to_string(),
                        None => return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::InvalidToken))
                    };

                    let params = match ncryptf::Authorization::extract_params_from_header_string(header) {
                        Ok(params) => params,
                        Err(_) => return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::InvalidToken))
                    };

                    match <$T>::get_token_from_access_token(params.access_token, &mut cache).await {
                        Ok(token) => {
                            // Create a new datetime from the data parameter, or the request header
                            let date: chrono::DateTime<Utc> = match params.date {
                                Some(date) => date,
                                None => {
                                    let date: chrono::DateTime<Utc> = match req.headers().get_one("X-Date") {
                                        Some(h) => {
                                            let date = chrono::DateTime::parse_from_rfc2822(&h.to_string());
                                            date.unwrap().with_timezone(&Utc)
                                        },
                                        None => return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::InvalidToken))
                                    };
                                    date
                                }
                            };

                            let method = req.method().to_string();
                            let uri = req.uri().to_string();
                            let data = body.to_owned();
                            match ncryptf::Authorization::from(
                                method,
                                uri,
                                token.clone(),
                                date,
                                data,
                                Some(params.salt),
                                params.version
                            ) {
                                Ok(auth) => {
                                    if auth.verify(params.hmac, ncryptf::rocket::NCRYPTF_DRIFT_ALLOWANCE) {
                                        // If the header is ncryptf, then also check the signing public key and do a constant time check
                                        match req.headers().get_one("Content-Type") {
                                            Some(ct) => {
                                                match ct {
                                                    ncryptf::rocket::NCRYPTF_CONTENT_TYPE => {
                                                        let version = req.local_cache(|| ncryptf::rocket::NcryptfRequestVersion(2));
                                                        if !body.eq("") && version.0 >= 2 {
                                                            let raw_body_s = req.local_cache(|| ncryptf::rocket::NcryptfRawBody("".to_string()));
                                                            let raw_body = &raw_body_s.0;
                                                            match ncryptf::Response::get_signing_public_key_from_response(base64::decode(raw_body).unwrap()) {
                                                                Ok(public_key) => {
                                                                    let signature_pk = token.get_signature_public_key().unwrap();
                                                                    if !constant_time_eq::constant_time_eq(&public_key, &signature_pk) {
                                                                        return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::SignatureInvalid));
                                                                    }
                                                                },
                                                                Err(_) => return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::SignatureInvalid))
                                                            }
                                                        }
                                                    },
                                                    _ => {}
                                                }
                                            },
                                            None => {}
                                        };
                                        match <$T>::get_user_from_token(token, &mut cache).await {
                                            Ok(user) => return Outcome::Success(*user),
                                            Err(_) => return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::InvalidToken))
                                        };
                                    }
                                },
                                Err(_) => return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::InvalidToken))
                            };
                        },
                        Err(_) => return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::InvalidToken))
                    };

                    return Outcome::Failure((rocket::http::Status::Unauthorized, TokenError::InvalidToken))
                }
            }
        }
    }
}

pub use auth as RocketAuth;