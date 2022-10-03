use base64;
use chrono::TimeZone;
use ncryptf::*;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;

#[derive(Debug, Clone)]
struct ApiTest {
    pub url: Option<String>,
    pub key: Keypair,
    pub token: Option<String>
}

impl ApiTest {
    pub fn setup() -> Self {
        let token = match std::env::var("ACCESS_TOKEN") {
            Ok(s) => Some(s),
            _ => None
        };

        let url = match std::env::var("NCRYPTF_TEST_API") {
            Ok(s) => Some(s),
            _ => Some("http://127.0.0.1:8080".to_string())
        };

        return ApiTest {
            url: url,
            key: Keypair::new(),
            token: token
        }
    }

    pub fn get_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, HeaderValue::from_str("application/vnd.ncryptf+json").unwrap());
        headers.insert(reqwest::header::ACCEPT, HeaderValue::from_str("application/vnd.ncryptf+json").unwrap());

        if self.token.is_some() {
            headers.insert(
                "X-Access-Token",
                HeaderValue::from_str(self.token.clone().unwrap().as_str()).unwrap()
            );
        }

        return headers;
    }
}

fn bootstrap() -> Option<serde_json::Value> {
    let client = reqwest::blocking::Client::new();
    let c = ApiTest::setup();

    let result = client.get(format!("{}/ek", c.clone().url.unwrap()))
        .headers(c.get_headers())
        .header("x-pubkey", base64::encode(c.clone().key.get_public_key()))
        .send();

    match result {
        Err(_error) => {
            assert!(false);
            return None;
        },
        Ok(resp) => {
            let r = ncryptf::Response::from(c.clone().key.get_secret_key());
            assert!(r.is_ok());
            let response = r.unwrap();
            assert_eq!(resp.status(), 200);

            let data = base64::decode(resp.text().unwrap());
            let d = response.decrypt(data.unwrap(), None, None);
            assert!(d.is_ok());
            let plain = d.unwrap();
            let json: serde_json::Value = serde_json::from_str(&plain.as_str()).unwrap();

            if json.get("hash-id").is_none() {
                assert!(false);
            }

            if json.get("public").is_none() {
                assert!(false);
            }

            if json.get("signature").is_none() {
                assert!(false);
            }

            return Some(json);
        }
    }
}

#[test]
fn test_ephemeral_key_bootstrap() {
    bootstrap();
}

#[test]
fn test_unauthenticated_encrypted_request() {
    let stack: serde_json::Value = match bootstrap() {
        None => {
            assert!(false);
            panic!("Test aborted");
        }
        Some(s) => s
    };

    let client = reqwest::blocking::Client::new();
    let c = ApiTest::setup();

    let sk = Signature::new();
    let mut request = match ncryptf::Request::from(
        c.clone().key.get_secret_key(),
        sk.clone().get_secret_key()
    ) {
        Err(_) => {
            assert!(false);
            panic!("Test aborted")
        },
        Ok(request) => request
    };
    let pk = stack.get("public").unwrap().as_str().unwrap();

    let payload: serde_json::Value = serde_json::from_str(r#"{ "hello": "world" }"#).unwrap();
    let encrypted_payload = match request.encrypt(
        payload.to_string(),
        base64::decode(pk).unwrap()
    ) {
        Ok(ec) => base64::encode(ec),
        Err(_error) => {
            dbg!(_error);
            assert!(false);
            panic!("Test aborted");
        }
    };

    let result = client.post(format!("{}/echo", c.clone().url.unwrap()))
        .body(encrypted_payload)
        .headers(c.get_headers())
        .header("x-hashid".to_string(), stack.get("hash-id").unwrap().as_str().unwrap());

    match result.send() {
        Err(_) => {
            assert!(false);
            panic!("test aborted")
        },
        Ok(resp) => {
            assert_eq!(resp.status(), 200);
            let r = Response::from(c.clone().key.get_secret_key());
            assert!(r.is_ok());
            let response = r.unwrap();

            let data = base64::decode(resp.text().unwrap());
            let d = response.decrypt(data.unwrap(), None, None);
            assert!(d.is_ok());
            let plain = d.unwrap();
            let json: serde_json::Value = serde_json::from_str(&plain.as_str()).unwrap();
            // These should be identical
            assert_eq!(json, payload);
        }
    }
}

#[test]
fn test_authenticated_encrypted_request() {
    let stack: serde_json::Value = match bootstrap() {
        None => {
            assert!(false);
            panic!("Test aborted");
        }
        Some(s) => s
    };

    let client = reqwest::blocking::Client::new();
    let c = ApiTest::setup();

    let sk = Signature::new();
    let mut request = match ncryptf::Request::from(
        c.clone().key.get_secret_key(),
        sk.clone().get_secret_key()
    ) {
        Err(_) => {
            assert!(false);
            panic!("Test aborted")
        },
        Ok(request) => request
    };
    let pk = stack.get("public").unwrap().as_str().unwrap();

    let payload: serde_json::Value = serde_json::from_str(r#"{
        "email": "clara.oswald@example.com",
        "password": "c0rect h0rs3 b@tt3y st@Pl3"
    }"#).unwrap();
    let encrypted_payload = match request.encrypt(
        payload.to_string(),
        base64::decode(pk).unwrap()
    ) {
        Ok(ec) => base64::encode(ec),
        Err(_error) => {
            assert!(false);
            panic!("Test aborted");
        }
    };

    let result = client.post(format!("{}/authenticate", c.clone().url.unwrap()))
        .body(encrypted_payload)
        .headers(c.get_headers())
        .header("x-hashid".to_string(), stack.get("hash-id").unwrap().as_str().unwrap());

    match result.send() {
        Err(_) => {
            assert!(false);
            panic!("test aborted")
        },
        Ok(resp) => {
            assert_eq!(resp.status(), 200);
            let r = Response::from(c.clone().key.get_secret_key());
            assert!(r.is_ok());
            let response = r.unwrap();

            let data = base64::decode(resp.text().unwrap());
            let d = response.decrypt(data.unwrap(), None, None);
            assert!(d.is_ok());
            let plain = d.unwrap();
            let json: serde_json::Value = serde_json::from_str(&plain.as_str()).unwrap();

            if json.get("access_token").is_none() {
                assert!(false);
            }

            if json.get("refresh_token").is_none() {
                assert!(false);
            }

            if json.get("ikm").is_none() {
                assert!(false);
            }

            if json.get("signing").is_none() {
                assert!(false);
            }

            if json.get("expires_at").is_none() {
                assert!(false);
            }

            let token = Token::from_json(json);

            assert!(token.is_ok());

            let t = token.unwrap();

            // Perform an authenticated request
            let client = reqwest::blocking::Client::new();
            let c = ApiTest::setup();

            let mut request = match ncryptf::Request::from(
                c.clone().key.get_secret_key(),
                t.signature.clone()
            ) {
                Err(_) => {
                    assert!(false);
                    panic!("Test aborted")
                },
                Ok(request) => request
            };
            let pk = stack.get("public").unwrap().as_str().unwrap();

            let payload: serde_json::Value = serde_json::from_str(r#"{ "hello": "world" }"#).unwrap();
            let encrypted_payload = match request.encrypt(
                payload.to_string(),
                base64::decode(pk).unwrap()
            ) {
                Ok(ec) => base64::encode(ec),
                Err(_error) => {
                    dbg!(_error);
                    assert!(false);
                    panic!("Test aborted");
                }
            };

            let auth = Authorization::from("PUT".to_string(), "/echo".to_string(), t, chrono::offset::Utc::now(), payload.to_string(), None, None);
            let result = client.put(format!("{}/echo", c.clone().url.unwrap()))
                .body(encrypted_payload)
                .headers(c.get_headers())
                .header("Authorization".to_string(), auth.unwrap().get_header())
                .header("x-hashid".to_string(), stack.get("hash-id").unwrap().as_str().unwrap());

            match result.send() {
                Err(_) => {
                    assert!(false);
                    panic!("test aborted")
                },
                Ok(resp) => {
                    assert_eq!(resp.status(), 200);
                    let r = Response::from(c.clone().key.get_secret_key());
                    assert!(r.is_ok());
                    let response = r.unwrap();

                    let data = base64::decode(resp.text().unwrap());
                    let d = response.decrypt(data.unwrap(), None, None);
                    assert!(d.is_ok());
                    let plain = d.unwrap();
                    let json: serde_json::Value = serde_json::from_str(&plain.as_str()).unwrap();
                    // These should be identical
                    assert_eq!(json, payload);
                }
            }
        }
    }
}