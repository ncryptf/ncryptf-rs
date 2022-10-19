use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResponseError {
    #[error("decrypting response to plain text failed.")]
    DecryptingResponseFailed,
    #[error("the remote server is not implemented correctly.")]
    ResponseImplementationError,
    #[error("the server did not return a response.")]
    ResponseMissing,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub response: InternalResponse
}

#[derive(Debug, Clone)]
pub struct InternalResponse {
    pub status: reqwest::StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub body: Option<String>,
    pub pk: Option<Vec<u8>>,
    pub sk: Option<Vec<u8>>
}

impl Response {
    /// Constructs a new response
    pub async fn new(response: reqwest::Response, sk: Vec<u8>) -> Result<Self, ResponseError> {
        let mut r = Self {
            response: InternalResponse {
                status: response.status(),
                headers: response.headers().to_owned(),
                body: None,
                pk: None,
                sk: None
            }
        };

        match response.text().await {
            Ok(body) => {
                match r.response.headers.get("Content-Type") {
                    Some(h) => match h.to_str() {
                        // If this is an NCRYPTF response, we need to decrypt it
                        Ok(crate::rocket::NCRYPTF_CONTENT_TYPE) => {
                            // If the body is empty, don't attempt to decrypt the response
                            if body.is_empty() {
                                r.response.body = None;
                                return Ok(r);
                            }
                            let body_bytes = base64::decode(body).unwrap();
                            let ncryptf_response = crate::Response::from(sk.clone()).unwrap();
                            match ncryptf_response.decrypt(body_bytes.clone(), None, None) {
                                Ok(message) =>  {
                                    // If we've already decrypted the response then these will succeed
                                    let pk =crate::Response::get_public_key_from_response(body_bytes.clone()).unwrap();
                                    let sk = crate::Response::get_signing_public_key_from_response(body_bytes.clone()).unwrap();
                                    r.response.body = Some(message);
                                    r.response.pk = Some(pk);
                                    r.response.sk = Some(sk);
                                    return Ok(r);
                                },
                                Err(_error) => return Err(ResponseError::DecryptingResponseFailed)
                            }
                        },
                        _ => {
                            if body.is_empty() {
                                r.response.body = None
                            } else {
                                r.response.body = Some(body)
                            }

                            return Ok(r);
                        }
                    },
                    // If we don't have a content type on the return, then the server isn't implemented
                    // correctly. We cannot proceed.
                    _ => return Err(ResponseError::ResponseImplementationError)
                }
            },
            // There's no response
            Err(_error) => return Err(ResponseError::ResponseMissing)
        }
    }

    /// Converts the response into an actual struct object
    pub fn into<T: for<'a> serde::Deserialize<'a>>(self) -> Result<T, serde_json::Error> {
        return serde_json::from_str::<T>(&self.response.body.unwrap());
    }
}