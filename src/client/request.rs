use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RequestError {
    #[error("reqwest failed")]
    ReqwestError(#[from] reqwest::Error),
    #[error("unable to create authorization")]
    AuthConstructionError,
    #[error("bootstrapping encrypted requst failed.")]
    ReKeyError,
    #[error("handling the response failed")]
    HandlingResponse(#[from] crate::client::ResponseError),
    #[error("the argument provided was not one that can be handled")]
    InvalidArgument,
    #[error("the request could not be encrypted")]
    EncryptionError,
    #[error("the token provided has expired, and could not be renewed")]
    TokenExpired,
}

/// The client request simplifies creating, sending, and handling an ncryptf request and response by providing a
/// simplified API that utilizes reqwest underneath.
///
/// Requests can be constructed by calling:
///
/// ```rust
/// let mut request = ncryptf::client::Request::<T>::new(client, "https://www.ncryptf.com", Some(ncryptf::Token));
/// ```
/// Where `T` is an implementation of `UpdateTokenTrait`, which provides an essential function for handling refresh tokens.
/// When the Token object is updated, `UpdateTokenTrait::token_update` will be called with the new token for you to handle.
/// If you wish to handle this separatedly, you can use the `UpdateTokenImpl` dummy trait.
///
/// and then use the helper http verb methods to make an request, which will automatically handle setting up an encrypted request
/// for you which includes bootstraping a new encryption key from a compliant server, and encrypting the request with a one-time encryption key
/// that is thrown away at the end of the request
///
/// ```rust
/// let response: ncryptf::Client::Response = request.get("/user/1").await.unwrap();
/// let response: ncryptf::Client::Response = request.delete("/user/1").await.unwrap();
/// let response: ncryptf::Client::Response = request.post("/user", "{ ... json ...}").await.unwrap();
/// let response: ncryptf::Client::Response = request.put("/user/1", "{ .. json ..}").await.unwrap();
/// ```
///
/// > NOTE: Only GET, DELETE, POST, PATHCH, and PUT verbs are supported for this client library -- you likely do not need to have an encrypted HEAD, or OPTIONS for an API.
///
/// An `ncryptf::Client::Response` is emitted on success. The response automatically handles decrypting the response for your application.
#[derive(Debug, Clone)]
pub struct Request<T: UpdateTokenTrait> {
    pub client: reqwest::Client,
    pub endpoint: String,
    pub token: Option<crate::Token>,
    pub cb: Option<T>,
    ek: Option<crate::rocket::ExportableEncryptionKeyData>,
}

pub trait UpdateTokenTrait: Send + Sync {
    /// Provides a post-callback // token update mechansim that can be controlled by the caller
    /// Necessary for Token refresh implementation
    fn token_update(&self, token: crate::Token) -> bool;
}

pub struct UpdateTokenImpl {}

impl UpdateTokenTrait for UpdateTokenImpl {
    fn token_update(&self, _token: crate::Token) -> bool {
        true
    }
}

impl<T: UpdateTokenTrait> Request<T> {
    /// Constructs a new request
    pub fn new(client: reqwest::Client, endpoint: &str, token: Option<crate::Token>) -> Self {
        Self {
            client,
            endpoint: endpoint.to_string(),
            token,
            cb: None,
            ek: None,
        }
    }

    /// Updates the token so the
    pub fn update_token(&mut self, token: Option<crate::Token>) {
        self.token = token;
    }

    /// This will bootstrap our request and get the necessary encryption keys to encrypt the request
    /// and decrypt the response
    /// This function is recursive, and will call itself until it ensures the underlying data is encrypted and non-readable
    #[async_recursion::async_recursion]
    pub async fn rekey(&mut self, hashid: Option<String>) -> Result<bool, RequestError> {
        let kp = crate::Keypair::new();
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Type",
            HeaderValue::from_str(&"application/json").unwrap(),
        );

        match hashid.clone() {
            Some(hashid) => {
                headers.insert(
                    "Accept",
                    HeaderValue::from_str(&"application/vnd.ncryptf+json").unwrap(),
                );
                headers.insert("X-HashId", HeaderValue::from_str(&hashid).unwrap());
                let pk = base64::encode(kp.get_public_key());
                headers.insert("X-PubKey", HeaderValue::from_str(&pk).unwrap());
            }
            _ => {
                headers.insert(
                    "Accept",
                    HeaderValue::from_str(&"application/json").unwrap(),
                );
            }
        };

        let furi = format!("{}{}", self.endpoint, "/ncryptf/ek");
        let builder = self.client.clone().get(furi).headers(headers);

        match self.do_request(builder, kp).await {
            Ok(response) => match response.status {
                reqwest::StatusCode::OK => match serde_json::from_str::<
                    crate::rocket::ExportableEncryptionKeyData,
                >(&response.body.unwrap())
                {
                    Ok(ek) => {
                        self.ek = Some(ek.clone());
                        match hashid.clone() {
                            Some(_) => return Ok(true),
                            _ => return self.rekey(Some(ek.hash_id)).await,
                        }
                    }
                    Err(_error) => return Err(RequestError::ReKeyError),
                },
                _ => return Err(RequestError::ReKeyError),
            },
            Err(_error) => return Err(RequestError::ReKeyError),
        };
    }

    /// Performs an HTTP GET request
    pub async fn get(&mut self, url: &str) -> Result<crate::client::Response, RequestError> {
        return self.execute("GET", url, None).await;
    }

    /// Performs an HTTP DELETE request
    pub async fn delete(&mut self, url: &str, payload: Option<&str>) -> Result<crate::client::Response, RequestError> {
        return self.execute("DELETE", url, payload).await;
    }

    /// Performs an HTTP PATCH request
    pub async fn patch(&mut self, url: &str, payload: Option<&str>) -> Result<crate::client::Response, RequestError> {
        return self.execute("PATCH", url, payload).await;
    }

    /// Performs an HTTP POST request
    pub async fn post(
        &mut self,
        url: &str,
        payload: Option<&str>,
    ) -> Result<crate::client::Response, RequestError> {
        return self.execute("POST", url, payload).await;
    }

    /// Performs an HTTP PUT request
    pub async fn put(
        &mut self,
        url: &str,
        payload: Option<&str>,
    ) -> Result<crate::client::Response, RequestError> {
        return self.execute("PUT", url, payload).await;
    }

    ///  Executes a request
    ///
    /// If a token is provided, the request is assumed to require authentication and the appropriate auth header is added
    /// GET requets are assumed to expect an encrypted response
    /// This will bootstrap the encryption process if necessary for an ncryptf encrypted response
    ///
    /// AsyncRecursion is to prevent Rust Compiler from detecting a loop - this method is not recursive.
    #[async_recursion::async_recursion]
    async fn execute(
        &mut self,
        method: &str,
        url: &str,
        payload: Option<&'async_recursion str>,
    ) -> Result<crate::client::Response, RequestError> {
        let payload_actual = match payload {
            Some(payload) => payload,
            None => ""
        };

        match &self.ek {
            Some(ek) => {
                if ek.is_expired() {
                    match self.rekey(None).await {
                        Ok(_) => {}
                        Err(error) => return Err(error),
                    };
                }
            }
            _ => match self.rekey(None).await {
                Ok(_) => {}
                Err(error) => return Err(error),
            },
        };

        let auth: Option<crate::Authorization> = match self.token.clone() {
            Some(mut token) => {
                // If the token has, or is nearing expiry, attempt to refresh it
                let expiration_limit = chrono::Utc::now().timestamp() + 120;
                if token.expires_at <= expiration_limit {
                    let refresh_token = token.refresh_token;
                    // Throw away this token
                    self.token = None;

                    match self
                        .post(
                            format!("/ncryptf/token/refresh?refresh_token={}", refresh_token)
                                .as_str(),
                            None,
                        )
                        .await
                    {
                        Ok(response) => match response.status {
                            reqwest::StatusCode::OK => match response.into::<crate::Token>() {
                                Ok(tt) => {
                                    self.token = Some(tt.clone());
                                    token = tt.clone();
                                    match &self.cb {
                                        Some(callback) => callback.token_update(tt.clone()),
                                        None => false
                                    };
                                }
                                Err(_error) => return Err(RequestError::TokenExpired),
                            },
                            _ => return Err(RequestError::TokenExpired),
                        },
                        Err(_error) => return Err(RequestError::TokenExpired),
                    };
                }

                // For requests with tokens, attempt to generate an Authorization struct
                match crate::Authorization::from(
                    method.to_string(),
                    url.to_string().clone(),
                    token.clone(),
                    Utc::now(),
                    payload_actual.to_string(),
                    None,
                    None,
                ) {
                    Ok(auth) => Some(auth),
                    Err(_error) => return Err(RequestError::AuthConstructionError),
                }
            }
            None => None,
        };

        let kp = crate::Keypair::new();

        let mut headers = HeaderMap::new();
        headers.insert(
            "Accept",
            HeaderValue::from_str(&"application/vnd.ncryptf+json").unwrap(),
        );
        // We always send the headers incase the request don't have a body
        headers.insert(
            "X-PubKey",
            HeaderValue::from_str(&base64::encode(kp.get_public_key())).unwrap(),
        );
        headers.insert(
            "X-HashId",
            HeaderValue::from_str(&self.ek.clone().unwrap().hash_id).unwrap(),
        );

        match auth {
            Some(auth) => {
                headers.insert(
                    "Authorization",
                    HeaderValue::from_str(auth.get_header().as_str()).unwrap(),
                );
            }
            _ => {}
        }

        let furi = format!("{}{}", self.endpoint, url);
        let mut builder: reqwest::RequestBuilder = match method {
            "GET" => self.client.clone().get(furi),
            "POST" => self.client.clone().post(furi),
            "PUT" => self.client.clone().put(furi),
            "DELETE" => self.client.clone().delete(furi),
            _ => return Err(RequestError::InvalidArgument),
        };

        match payload_actual {
            "" => {
                headers.insert(
                    "Content-Type",
                    HeaderValue::from_str(&"application/json").unwrap(),
                );
            }
            _ => {
                headers.insert(
                    "Content-Type",
                    HeaderValue::from_str(&"application/vnd.ncryptf+json").unwrap(),
                );
                let sk = match self.token.clone() {
                    Some(token) => token.signature,
                    None => {
                        let sk = crate::Signature::new();
                        sk.get_secret_key()
                    }
                };

                let mut request = crate::Request::from(kp.get_secret_key(), sk).unwrap();
                match request.encrypt(
                    payload_actual.to_string(),
                    self.ek.as_ref().unwrap().clone().get_public_key().unwrap(),
                ) {
                    Ok(body) => {
                        builder = builder.body(base64::encode(body));
                    }
                    Err(_error) => return Err(RequestError::EncryptionError),
                }
            }
        }

        builder = builder.headers(headers);

        return self.do_request(builder, kp).await;
    }

    /// Internal method to perform the http request
    async fn do_request(
        &mut self,
        builder: reqwest::RequestBuilder,
        kp: crate::Keypair,
    ) -> Result<crate::client::Response, RequestError> {
        match builder.send().await {
            Ok(response) => {
                // If the key is ephemeral or expired, we need to purge it so future requests don't use it
                // We can handle re-keying on the next request
                if self.ek.is_some() {
                    if self.ek.clone().unwrap().ephemeral || self.ek.clone().unwrap().is_expired() {
                        self.ek = None;
                    }
                }

                let result = match crate::client::Response::new(response, kp.get_secret_key()).await
                {
                    Ok(response) => response,
                    Err(error) => return Err(RequestError::HandlingResponse(error)),
                };

                // Opportunistically update the encryption key headers
                let hash_id = self.get_header_by_name(result.headers.get("x-hashid"));
                let expires_at =
                    self.get_header_by_name(result.headers.get("x-public-key-expiration"));
                let public_key = self.get_key_string_by_result_or_header(
                    result.pk.clone(),
                    result.headers.get("x-public-key"),
                );
                let signature_key = self.get_key_string_by_result_or_header(
                    result.sk.clone(),
                    result.headers.get("x-signature-key"),
                );
                if hash_id.is_some()
                    && expires_at.is_some()
                    && public_key.is_some()
                    && signature_key.is_some()
                {
                    let xp = expires_at.unwrap().parse::<i64>();
                    if xp.is_ok() {
                        self.ek = Some(crate::rocket::ExportableEncryptionKeyData {
                            public: public_key.unwrap(),
                            signature: signature_key.unwrap(),
                            hash_id: hash_id.unwrap(),
                            ephemeral: false,
                            expires_at: xp.unwrap(),
                        });
                    }
                }

                return Ok(result);
            }
            Err(error) => Err(RequestError::ReqwestError(error)),
        }
    }

    /// Helper method to get the key material from either the response body or the headers
    fn get_key_string_by_result_or_header(
        &self,
        key: Option<Vec<u8>>,
        header: Option<&HeaderValue>,
    ) -> Option<String> {
        match key {
            // If we have a key from the response, base64 encode and return it
            Some(key) => Some(base64::encode(key)),
            // If we don't have a key check the header
            None => match header {
                Some(header) => match header.to_str() {
                    // The header will already be base64 encoded, return it directly.
                    Ok(s) => Some(s.to_string()),
                    Err(_) => None,
                },
                None => None,
            },
        }
    }

    /// Helper method to grab a given header by its name
    fn get_header_by_name(&self, header: Option<&HeaderValue>) -> Option<String> {
        match header {
            Some(h) => match h.to_str() {
                Ok(s) => Some(s.to_string()),
                Err(_) => None,
            },
            None => None,
        }
    }
}
