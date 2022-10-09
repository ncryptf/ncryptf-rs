use async_trait::async_trait;

// A error representing
#[derive(Clone, Debug)]
pub enum TokenError {
    InvalidToken,
    ServerError
}

#[async_trait]
pub trait AuthorizationTrait: Sync + Send + 'static {
    async fn get_token_from_access_token(access_token: String) -> Result<crate::Token, TokenError>;
    async fn get_user_from_token(token: crate::Token) -> Result<Box<Self>, TokenError>;
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

                    let cache = match ncryptf::rocket::get_cache(req) {
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

                    match <$T>::get_token_from_access_token(params.access_token).await {
                        Ok(token) => {
                            // Create a new datetime from the data parameter, or the request header
                            let date = Utc::now();

                            match ncryptf::Authorization::from(
                                req.method().to_string(),
                                req.uri().to_string(),
                                token.clone(),
                                date,
                                body.to_owned(),
                                Some(params.salt),
                                params.version
                            ) {
                                Ok(auth) => {
                                    if auth.verify(params.hmac, ncryptf::rocket::NCRYPTF_DRIFT_ALLOWANCE) {
                                        // If the header is ncryptf, then also check the signing public key and do a constant time check

                                        match <$T>::get_user_from_token(token).await {
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