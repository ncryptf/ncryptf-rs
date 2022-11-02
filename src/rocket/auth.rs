#[doc(hidden)]
pub use base64;
#[doc(hidden)]
pub use chrono::{DateTime, Utc};
#[doc(hidden)]
pub use constant_time_eq;
#[doc(hidden)]
pub use rocket::{
    async_trait,
    http::Status,
    request::{self, FromRequest, Outcome, Request},
};
#[doc(hidden)]
pub use rocket_db_pools::figment::Figment;

/// An enum of the various authentication errors that may occur - generalized
#[derive(Debug)]
pub enum TokenError {
    InvalidToken,
    SignatureInvalid,
    ServerError,
}

/// AuthorizationTrait is a trait that should be implemented by your User entity.
/// This trait, in conjunction with the ncryptf::auth!() macro, enables individual
/// Users to be returned as part of a Rocket request guard.
#[async_trait::async_trait]
pub trait AuthorizationTrait: Sync + Send + 'static {
    /// Returns a ncryptf::Token instance given an access_token. The `databases.*` figment is provided to construct the relevant database connections as needed to process this request.
    async fn get_token_from_access_token(
        access_token: String,
        figment: Figment,
    ) -> Result<crate::Token, TokenError>;

    /// Returns a <Self> (User) entity given a specific token
    /// You can use this method to determine the appropriate access credentials, scoping, and permissions.
    /// The `databases.*` figment is provided to construct the relevant database connections as needed to process this request.
    async fn get_user_from_token(
        token: crate::Token,
        figment: Figment,
    ) -> Result<Box<Self>, TokenError>;
}

/// The ncryptf::auth!() macro provides the appropriate generic implementation details of FromRequest to allow User entities to be returned
/// as a Rocket request guard (FromRequest). The core features of ncryptf authorization verification are implemented through this macro.
/// If you wish to utilize ncryptf's authorization features you must perform the following.
///
/// ### Usage
/// 1. Attach the ncryptf::Fairing to your Rocket configuration:
///  ```rust
///  let rocket = rocket::custom(config)
///      .attach(NcryptfFairing);
///  ```
///  2. Define your User entity, and have to implement AuthorizationTrait.
///  3. At the end of your User entity struct file, bind the macro FromRequest to your User entity.
///  ```rust
///  ncryptf::auth!(User);
///  ```
///  4. Your User is now available as part of the request guard:
///  ```
///  #[post("/auth_info", data="<data>")]
///  fn auth_echo(_user: User){
///      dbg!(_user);
///  }
///  ```
///  **NOTE**: The Authorization Features of ncryptf are exclusively available if and only if you set the appropriate Content-Type to either application/json, or application/vnd.ncryptf+json, _even for GET requests_,
///  and other requests that don't have a body. The FromRequest functionality is only available for these content types.
///  Additionally, ncryptf::rocket::Json will handle all JSON + Ncryptf+JSON content types when this is in use. ncryptf::rocket::Json is mostly compatible with rocket::serde::Json, but shares the same limitations, features,
///  and particularities.
#[macro_export]
macro_rules! auth {
    ($T: ty) => {
        use $crate::rocket::TokenError;
        use $crate::rocket::AuthorizationTrait;
        use $crate::Authorization;
        #[$crate::rocket::async_trait]
        impl<'r>$crate::rocket::request::FromRequest<'r> for $T {
            type Error = TokenError;

            async fn from_request(req: &'r $crate::rocket::request::Request<'_>) ->$crate::rocket::Outcome<Self, TokenError> {
                let dbs = req.rocket().figment().focus("databases");

                let body = req.local_cache(|| return "".to_string());

                // Retrieve the Authorization header
                let header: String = match req.headers().get_one("Authorization") {
                    Some(h) => h.to_string(),
                    None => return$crate::rocket::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                };

                let params = match $crate::Authorization::extract_params_from_header_string(header) {
                    Ok(params) => params,
                    Err(_) => return $crate::rocket::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                };

                match <$T>::get_token_from_access_token(params.access_token, dbs.clone()).await {
                    Ok(token) => {
                        // Create a new datetime from the data parameter, or the request header
                        let date: $crate::rocket::DateTime<$crate::rocket::Utc> = match params.date {
                            Some(date) => date,
                            None => {
                                let date: $crate::rocket::DateTime<$crate::rocket::Utc> = match req.headers().get_one("X-Date") {
                                    Some(h) => {
                                        let date = $crate::rocket::DateTime::parse_from_rfc2822(&h.to_string());
                                        date.unwrap().with_timezone(&$crate::rocket::Utc)
                                    },
                                    None => {
                                        return$crate::rocket::request::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken));
                                    }
                                };
                                date
                            }
                        };

                        let method = req.method().to_string();
                        let uri = req.uri().to_string();
                        let data = body.to_owned();
                        match $crate::Authorization::from(
                            method,
                            uri,
                            token.clone(),
                            date,
                            data,
                            Some(params.salt),
                            params.version
                        ) {
                            Ok(auth) => {
                                if auth.verify(params.hmac, $crate::rocket::NCRYPTF_DRIFT_ALLOWANCE) {
                                    // If the header is ncryptf, then also check the signing public key and do a constant time check
                                    match req.headers().get_one("Content-Type") {
                                        Some(ct) => {
                                            match ct {
                                                $crate::rocket::NCRYPTF_CONTENT_TYPE => {
                                                    let version = req.local_cache(|| $crate::rocket::NcryptfRequestVersion(2));
                                                    if !body.eq("") && version.0 >= 2 {
                                                        let raw_body_s = req.local_cache(|| $crate::rocket::NcryptfRawBody("".to_string()));
                                                        let raw_body = &raw_body_s.0;
                                                        match $crate::Response::get_signing_public_key_from_response($crate::rocket::base64::decode(raw_body).unwrap()) {
                                                            Ok(public_key) => {
                                                                let signature_pk = token.get_signature_public_key().unwrap();
                                                                if !$crate::rocket::constant_time_eq::constant_time_eq(&public_key, &signature_pk) {
                                                                    return$crate::rocket::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::SignatureInvalid));
                                                                }
                                                            },
                                                            Err(_) => return$crate::rocket::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::SignatureInvalid))
                                                        }
                                                    }
                                                },
                                                _ => {}
                                            }
                                        },
                                        None => {}
                                    };

                                    match <$T>::get_user_from_token(token, dbs).await {
                                        Ok(user) => return $crate::rocket::Outcome::Success(*user),
                                        Err(_) => return $crate::rocket::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                                    };
                                }
                            },
                            Err(_) => return $crate::rocket::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                        };
                    },
                    Err(_) => return $crate::rocket::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                };

                return $crate::rocket::Outcome::Failure(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
            }
        }
    }
}
