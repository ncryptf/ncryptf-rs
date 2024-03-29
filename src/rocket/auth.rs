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
    data::{FromData, Outcome},
    request::{self, Request},
};
#[doc(hidden)]
pub use rocket_db_pools::figment::Figment;

pub use serde::Deserialize;

/// An enum of the various authentication errors that may occur - generalized
#[derive(Debug)]
pub enum TokenError {
    InvalidToken,
    SignatureInvalid,
    InvalidRequest,
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

#[derive(Debug, Clone)]
pub struct RequestData<T: AuthorizationTrait> {
    pub identity: T,
    pub data: String
}

impl<T: AuthorizationTrait + Clone> RequestData<T> {
    pub fn get_identity(&self) -> T {
        return self.identity.clone();
    }

    pub fn get_data<D: crate::serde::DeserializeOwned>(&self) -> Result<crate::rocket::Json<D>, anyhow::Error> {
        match crate::rocket::Json::<D>::from_str(self.data.clone().as_str()) {
            Ok(s) => Ok(s),
            Err(e) => Err(anyhow::anyhow!(e.to_string()))
        }
    }
}

use crate::Authorization;

/// The Authenticated user can be retrieved on a HTTP Request with a body by setting the <data> attribute on your request to the following
/// ``
///  ```
///  #[post("/auth_info", data="<data>")]
///  fn auth_echo(_user: ncryptf::rocket::RequestData<User>){
///      dbg!(_user.identity); // The identity <User>
///      dbg!(_user.data) // The raw String data, convert to type struct via ncryptf::rocket::Json::<T>::from_str()
///  }
///  ```
#[crate::rocket::async_trait]
impl<'r, T: AuthorizationTrait> FromData<'r> for RequestData<T> {
    type Error = TokenError;

    async fn from_data(
        req: &'r rocket::request::Request<'_>,
        data: rocket::Data<'r>
    ) -> rocket::data::Outcome<'r, Self> {
        let _ = crate::rocket::parse_body::<serde_json::Value>(req, data).await;
        let dbs = req.rocket().figment().focus("databases");

        let body = req.local_cache(|| return "".to_string());

        // Retrieve the Authorization header
        let header: String = match req.headers().get_one("Authorization") {
            Some(h) => h.to_string(),
            None => return Outcome::Error((Status::Unauthorized, TokenError::InvalidToken))
        };

        let params = match crate::Authorization::extract_params_from_header_string(header) {
            Ok(params) => params,
            Err(_) => return Outcome::Error((Status::Unauthorized, TokenError::InvalidToken))
        };

        match <T>::get_token_from_access_token(params.access_token, dbs.clone()).await {
            Ok(token) => {
                // Create a new datetime from the data parameter, or the request header
                let date: crate::rocket::DateTime<Utc> = match params.date {
                    Some(date) => date,
                    None => {
                        let date: crate::rocket::DateTime<Utc> = match req.headers().get_one("X-Date") {
                            Some(h) => {
                                let date = crate::rocket::DateTime::parse_from_rfc2822(&h.to_string());
                                date.unwrap().with_timezone(&Utc)
                            },
                            None => {
                                return Outcome::Error((Status::Unauthorized, TokenError::InvalidToken));
                            }
                        };
                        date
                    }
                };

                let method = req.method().to_string();
                let uri = req.uri().to_string();
                let data = body.clone();
                match Authorization::from(
                    method,
                    uri,
                    token.clone(),
                    date,
                    data.clone().to_owned(),
                    Some(params.salt),
                    params.version
                ) {
                    Ok(auth) => {
                        if auth.verify(params.hmac, crate::rocket::NCRYPTF_DRIFT_ALLOWANCE) {
                            match <T>::get_user_from_token(token, dbs).await {
                                Ok(user) => return Outcome::Success(RequestData { identity: *user, data: data.clone() }),
                                Err(_) => return Outcome::Error((Status::Unauthorized, TokenError::InvalidToken))
                            };
                        }
                    },
                    Err(_) => return Outcome::Error((Status::Unauthorized, TokenError::InvalidToken))
                };
            },
            Err(_) => return Outcome::Error((Status::Unauthorized, TokenError::InvalidToken))
        };

        return Outcome::Error((Status::Unauthorized, TokenError::InvalidToken))
    }
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
///  #[get("/auth_info")]
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
        use rocket::request::{self, FromRequest, Outcome};

        #[$crate::rocket::async_trait]
        impl<'r> $crate::rocket::request::FromRequest<'r> for $T {
            type Error = TokenError;

            async fn from_request(req: &'r $crate::rocket::request::Request<'_>) -> rocket::request::Outcome<Self, TokenError> {
                let dbs = req.rocket().figment().focus("databases");

                let body = req.local_cache(|| return "".to_string());

                // Retrieve the Authorization header
                let header: String = match req.headers().get_one("Authorization") {
                    Some(h) => h.to_string(),
                    None => return rocket::request::Outcome::Error(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                };

                let params = match $crate::Authorization::extract_params_from_header_string(header) {
                    Ok(params) => params,
                    Err(_) => return rocket::request::Outcome::Error(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
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
                                        return rocket::request::Outcome::Error(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken));
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
                                    match <$T>::get_user_from_token(token, dbs).await {
                                        Ok(user) => return rocket::request::Outcome::Success(*user),
                                        Err(_) => return rocket::request::Outcome::Error(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                                    };
                                }
                            },
                            Err(_) => return rocket::request::Outcome::Error(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                        };
                    },
                    Err(_) => return rocket::request::Outcome::Error(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
                };

                return rocket::request::Outcome::Error(($crate::rocket::Status::Unauthorized, TokenError::InvalidToken))
            }
        }
    }
}