use async_trait::async_trait;

// A error representing
#[derive(Clone, Debug)]
pub enum TokenError {
    InvalidToken,
    SignatureInvalid,
    ServerError
}

#[async_trait]
pub trait AuthorizationTrait: Sync + Send + 'static {
    async fn get_token_from_access_token(access_token: String, cache:  &mut redis::Connection) -> Result<crate::Token, TokenError>;
    async fn get_user_from_token(token: crate::Token, cache: &mut redis::Connection) -> Result<Box<Self>, TokenError>;
}

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