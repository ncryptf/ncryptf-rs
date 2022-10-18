use chrono::Utc;
use thiserror::Error;
use reqwest::header::{HeaderMap, HeaderValue};

#[derive(Error, Debug)]
pub enum RequestError {
    #[error("reqwest failed")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Unable to create authorization")]
    AuthConstructionError,
    #[error("Bootstrapping encrypted requst failed.")]
    ReKeyError
}

/// Networking layer for requests
pub struct Request {
    pub client: reqwest::Client,
    pub endpoint: String,
    pub token: Option<crate::Token>,
    ek: Option<crate::rocket::ExportableEncryptionKeyData>
}

impl Request {
    /// Constructs a new request
    pub fn new(client: reqwest::Client, endpoint: &str, token: Option<crate::Token>) -> Self {
        Self {
            client: client,
            endpoint: endpoint.to_string(),
            token: token,
            ek: None
        }
    }

    /// This will bootstrap our request and get the necessary encryption keys to encrypt the request
    /// and decrypt the response
    /// This function is recursive, and will call itself until it ensures the underlying data is encrypted and non-readable
    #[async_recursion::async_recursion]
    pub async fn rekey(&mut self, hashid: Option<String>) -> Result<bool, RequestError> {
        let kp = crate::Keypair::new();
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_str(&"application/json").unwrap());

        match hashid.clone() {
            Some(hashid) => {
                headers.insert("Accept", HeaderValue::from_str(&"application/vnd.ncryptf+json").unwrap());
                headers.insert("X-HashId", HeaderValue::from_str(&hashid).unwrap());
                let pk = base64::encode(kp.get_public_key());
                headers.insert("X-PubKey", HeaderValue::from_str(&pk).unwrap());
            },
            _ => {
                headers.insert("Accept", HeaderValue::from_str(&"application/json").unwrap());
            }
        };

        let furi = format!("{}{}", self.endpoint, "/ncryptf/ek");
        let builder = self.client.clone().get(furi)
            .headers(headers);

        match builder.send().await {
            Ok(response) => match response.status() {
                reqwest::StatusCode::OK => {
                    let body = match hashid.clone() {
                        Some(_) => {
                            let resp = crate::Response::from(kp.get_secret_key()).unwrap();
                            let d = base64::decode(response.text().await.unwrap()).unwrap();
                            match resp.decrypt(d, Some(kp.get_public_key()), None) {
                                Ok(data) => data,
                                Err(_error) =>return Err(RequestError::ReKeyError)
                            }
                        },
                        _ => response.text().await.unwrap()
                    };

                    match serde_json::from_str::<crate::rocket::ExportableEncryptionKeyData>(&body) {
                        Ok(ek) => {
                            self.ek = Some(ek.clone());
                            match hashid.clone() {
                                Some(_) => return Ok(true),
                                _ => return self.rekey(Some(ek.hash_id)).await
                            }
                        },
                        Err(_error) => return Err(RequestError::ReKeyError)
                    };
                },
                _ => return Err(RequestError::ReKeyError)
            },
            Err(_error) => return Err(RequestError::ReKeyError)
        }
    }

    /// Performs a GET request
    ///
    /// If a token is provided, the request is assumed to require authentication and the appropriate auth header is added
    /// GET requets are assumed to expect an encrypted response
    /// This will bootstrap the encryption process if necessary for an ncryptf encrypted response
    pub async fn get(&mut self, url: &str) -> Result<reqwest::Response, RequestError> {
        match &self.ek {
            Some(ek) => {
                if ek.is_expired() {
                    match self.rekey(None).await {
                        Ok(_) => {},
                        Err(error) => return Err(error)
                    };
                }
            }
            _ => match self.rekey(None).await {
                Ok(_) => {},
                Err(error) => return Err(error)
            }
        };

        let auth: Option<crate::Authorization> = match self.token.clone() {
            Some(token) => match crate::Authorization::from(
                "GET".to_string(),
                url.to_string().clone(),
                token,
                Utc::now(),
                "".to_string(),
                None,
                None
            ) {
                Ok(auth) => Some(auth),
                Err(_error) => return Err(RequestError::AuthConstructionError)
            },
            None => None
        };

        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_str(&"application/json").unwrap());
        headers.insert("Accept", HeaderValue::from_str(&"application/json").unwrap());

        match auth {
            Some(auth) => {
                headers.insert("Authorization", HeaderValue::from_str(auth.get_header().as_str()).unwrap());
            }
            _ => {}
        }

        let furi = format!("{}{}", self.endpoint, url);
        let builder = self.client.clone().get(furi)
            .headers(headers);

        match builder.send().await {
            Ok(response) => {
                // If the key is ephemeral or expired, we need to purge it so future requests don't use it
                // We can handle re-keying on the next request
                if self.ek.clone().unwrap().ephemeral || self.ek.clone().unwrap().is_expired() {
                    self.ek = None;
                }

                // Use the headers to update the ek

                return Ok(response)
            },
            Err(error) => Err(RequestError::ReqwestError(error))
        }
    }
}