use ncryptf::{ek_route, randombytes_buf, rocket::ExportableEncryptionKeyData};
use rocket::{http::Header, local::blocking::Client, serde::Serialize};
use serde::Deserialize;
use base64::{Engine as _, engine::general_purpose};
use cached::Cached;

// This is a mock user used to simplify return data
#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
}

// Implement the Authorization Trait
#[async_trait]
impl ncryptf::rocket::AuthorizationTrait for User {
    /// Our static implementation returns a static token
    async fn get_token_from_access_token(
        _access_token: String,
        _f: rocket::figment::Figment,
    ) -> Result<ncryptf::Token, ncryptf::rocket::TokenError> {
        let now = chrono::Utc::now().timestamp();

        let token =  ncryptf::Token::from(
            "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J".to_string(),
            "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8".to_string(),
            general_purpose::STANDARD.decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
            general_purpose::STANDARD.decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
            now + 14400
        ).unwrap();

        return Ok(token);
    }

    /// Returns a static user from an authorization token
    async fn get_user_from_token(
        _token: ncryptf::Token,
        _f: rocket::figment::Figment,
    ) -> Result<Box<Self>, ncryptf::rocket::TokenError> {
        return Ok(Box::new(User { id: 1 }));
    }
}

/// A simple test struct
#[derive(Deserialize, Serialize, Clone, Debug)]
struct TestStruct {
    pub hello: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct ExampleStruct {
    pub f: String,
    pub g: String,
    pub h: String,
}

#[post("/echo2", data = "<data>")]
fn echo2(data: ncryptf::rocket::Json<ExampleStruct>) -> ncryptf::rocket::Json<ExampleStruct> {
    return ncryptf::rocket::Json(data.0);
}

#[post("/echo", data = "<data>")]
fn echo(data: ncryptf::rocket::Json<TestStruct>) -> ncryptf::rocket::Json<TestStruct> {
    return ncryptf::rocket::Json(data.0);
}

#[post("/auth_echo", data = "<data>")]
fn auth_echo(
    data: ncryptf::rocket::RequestData<User> // Satisfying the reqest guard is sufficient to verify the request can be parsed
) ->  ncryptf::rocket::Json<TestStruct> {
    return data.get_data::<TestStruct>().unwrap();
}

ncryptf::auth!(User);
#[get("/auth_only")]
fn auth_only(
    _user: User
) -> ncryptf::rocket::Json<TestStruct> {
    let t = TestStruct { 
        hello: "world".to_string()
    };
    return ncryptf::rocket::Json::<TestStruct>(t);
}

/// Setup helper function
fn setup() -> Client {
    let cache = get_or_create_cache();
    let config = rocket::Config::figment()
        .merge(("ident", false))
        .merge(("log_level", rocket::config::LogLevel::Normal));

    ek_route!();

    // Create a CacheWrapper with our TimedCache
    let cache_wrapper = ncryptf::rocket::CacheWrapper::TimedCache(cache);

    let rocket = rocket::custom(config)
        .manage(cache_wrapper)
        .mount("/", routes![echo, auth_echo, echo2, auth_only])
        .mount("/ncryptf", routes![ncryptf_ek_route]);
    
    return match Client::untracked(rocket) {
        Ok(client) => client,
        Err(_error) => {
            dbg!(_error);
            panic!("Failed to create client");
        }
    };
}

use std::sync::{Arc, Mutex};

// Global cache for testing - this allows get_ek() to share the same cache as the Rocket instance
static GLOBAL_CACHE: std::sync::OnceLock<Arc<Mutex<cached::TimedCache<String, ncryptf::rocket::EncryptionKey>>>> = std::sync::OnceLock::new();

fn get_or_create_cache() -> Arc<Mutex<cached::TimedCache<String, ncryptf::rocket::EncryptionKey>>> {
    GLOBAL_CACHE.get_or_init(|| {
        let cache = cached::TimedCache::with_lifespan_and_refresh(
            std::time::Duration::from_secs(3600),
            true
        );
        Arc::new(Mutex::new(cache))
    }).clone()
}

fn get_ek() -> ncryptf::rocket::EncryptionKey {
    let ek = ncryptf::rocket::EncryptionKey::new(false);
    
    // Store in the shared cache
    let cache = get_or_create_cache();
    if let Ok(mut cache_guard) = cache.lock() {
        cache_guard.cache_set(ek.get_hash_id(), ek.clone());
    }

    return ek;
}

/// Verifies that the ncryptf_ek_route export Macro generates appropriately and can be called
#[test]
fn test_ek_route_plain() {
    let client = setup();
    let response = client
        .get("/ncryptf/ek")
        .header(Header::new("Content-Type", "application/json"))
        .header(Header::new("Accept", "application/json"))
        .dispatch();

    // We should get an HTTP 200 back
    assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    match serde_json::from_str::<ExportableEncryptionKeyData>(&body) {
        Ok(json) => {
            assert_ne!(json.hash_id, "".to_string());
            assert_ne!(json.public, "".to_string());
            assert_ne!(json.signature, "".to_string());

            // Verify that the data is the correct length and that we deserialized the struct correctly.
            let signature = general_purpose::STANDARD.decode(json.signature);
            let public = general_purpose::STANDARD.decode(json.public);
            assert!(signature.is_ok());
            assert!(public.is_ok());
            let s = signature.unwrap();
            let p = public.unwrap();

            assert_eq!(s.len(), 32);
            assert_eq!(p.len(), 32);
        }
        Err(_) => {
            return assert!(false);
        }
    }
}

/// This will send an ncryptf encrypted message, and should receive back an ncryptf encrypted response
#[test]
fn test_echo() {
    let client = setup();

    let ek = get_ek();
    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    let kp = ncryptf::Keypair::new();
    let sk = ncryptf::Signature::new();
    let req = ncryptf::Request::from(kp.get_secret_key(), sk.get_secret_key());

    let req_body = req
        .unwrap()
        .encrypt(json.to_string(), ek.get_box_kp().get_public_key())
        .unwrap();
    let astr = general_purpose::STANDARD.encode(req_body.clone());

    let vr = ncryptf::Response::get_version(req_body.clone());
    assert_eq!(vr.unwrap(), 2);

    let response = client
        .post("/echo")
        .body(astr)
        .header(Header::new("Content-Type", "application/vnd.ncryptf+json"))
        .header(Header::new("Accept", "application/vnd.ncryptf+json"))
        .header(Header::new("X-HashId", ek.get_hash_id()))
        .dispatch();

    // We should get an HTTP 200 back
    assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    let bbody = general_purpose::STANDARD.decode(body.clone()).unwrap();
    let r = ncryptf::Response::from(kp.get_secret_key()).unwrap();

    let message = r.decrypt(bbody, None, None);
    assert!(message.is_ok());
    assert_eq!(message.unwrap(), json.to_string());
}

/// This will send an ncryptf encrypted message, but will recieve back a plaintext message
#[test]
fn test_echo_plain() {
    let client = setup();

    let ek = get_ek();
    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    let kp = ncryptf::Keypair::new();
    let sk = ncryptf::Signature::new();
    let req = ncryptf::Request::from(kp.get_secret_key(), sk.get_secret_key());

    let body = req
        .unwrap()
        .encrypt(json.to_string(), ek.get_box_kp().get_public_key())
        .unwrap();
    assert_eq!(body.clone().len(), 253);
    let astr = general_purpose::STANDARD.encode(body.clone());

    let response = client
        .post("/echo")
        .body(astr)
        .header(Header::new("Content-Type", "application/vnd.ncryptf+json"))
        .header(Header::new("Accept", "application/json"))
        .header(Header::new("X-HashId", ek.get_hash_id()))
        .dispatch();

    let body = response.into_string().unwrap();
    assert_eq!(body, json.to_string());
}

/// Tests that ncryptf responses can be emitted from a plain text request
#[test]
fn test_echo_plain_to_encrypted() {
    let client = setup();

    let ek = get_ek();
    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    let kp = ncryptf::Keypair::new();

    let response = client
        .post("/echo")
        .body(json.to_string())
        .header(Header::new("Content-Type", "application/json"))
        .header(Header::new("Accept", "application/vnd.ncryptf+json"))
        .header(Header::new("X-HashId", ek.get_hash_id()))
        .header(Header::new("X-PubKey", general_purpose::STANDARD.encode(kp.get_public_key())))
        .dispatch();

    // We should get an HTTP 200 back
    assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    let bbody = general_purpose::STANDARD.decode(body.clone()).unwrap();
    let r = ncryptf::Response::from(kp.get_secret_key()).unwrap();

    let message = r.decrypt(bbody, None, None);
    assert!(message.is_ok());
    assert_eq!(message.unwrap(), json.to_string());
}

#[test]
fn test_echo_plain_to_plain() {
    let client = setup();
    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    let response = client
        .post("/echo")
        .body(json.to_string())
        .header(Header::new("Content-Type", "application/json"))
        .header(Header::new("Accept", "application/json"))
        .dispatch();

    // We should get an HTTP 200 back
    //assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    assert_eq!(body, json.to_string());
}

#[test]
fn test_auth_echo_plain_to_plain() {
    let client = setup();
    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    // Always use the current time
    let now = chrono::Utc::now().timestamp();

    // We really only care about the ikm and signature
    // This information should be extracted from a local cache
    let token =  ncryptf::Token::from(
        "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J".to_string(),
        "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8".to_string(),
        general_purpose::STANDARD.decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
        general_purpose::STANDARD.decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
        now + 14400
    ).unwrap();

    let auth = match ncryptf::Authorization::from(
        "POST".to_string(),
        "/auth_echo".to_string(),
        token,
        chrono::Utc::now(),
        json.clone().to_string(),
        None,
        Some(2),
    ) {
        Ok(auth) => auth,
        Err(_) => {
            assert!(false);
            panic!("unable to generate auth header")
        }
    };

    let response = client
        .post("/auth_echo")
        .body(json.to_string())
        .header(Header::new("Authorization", auth.get_header()))
        .header(Header::new("Content-Type", "application/json"))
        .header(Header::new("Accept", "application/json"))
        .dispatch();

    // We should get an HTTP 200 back
    assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    assert_eq!(body, json.to_string());
}

#[test]
fn test_auth_get() {
    let client = setup();

    // Always use the current time
    let now = chrono::Utc::now().timestamp();

    // We really only care about the ikm and signature
    // This information should be extracted from a local cache
    let token =  ncryptf::Token::from(
        "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J".to_string(),
        "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8".to_string(),
        general_purpose::STANDARD.decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
        general_purpose::STANDARD.decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
        now + 14400
    ).unwrap();

    let auth = match ncryptf::Authorization::from(
        "GET".to_string(),
        "/auth_only".to_string(),
        token,
        chrono::Utc::now(),
        "".to_string(),
        None,
        Some(2),
    ) {
        Ok(auth) => auth,
        Err(_) => {
            assert!(false);
            panic!("unable to generate auth header")
        }
    };

    let response = client
        .get("/auth_only")
        .header(Header::new("Authorization", auth.get_header()))
        .header(Header::new("Content-Type", "application/json"))
        .header(Header::new("Accept", "application/json"))
        .dispatch();


    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    // We should get an HTTP 200 back
    assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    assert_eq!(body, json.to_string());
}

/// Tests an authenticated echo request with a signature and auth header.
#[test]
fn test_auth_echo_encrypted_to_plain() {
    let client = setup();

    let ek = get_ek();
    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    let kp = ncryptf::Keypair::new();

    // Always use the current time
    let now = chrono::Utc::now().timestamp();

    // We really only care about the ikm and signature
    // This information should be extracted from a local cache
    let token =  ncryptf::Token::from(
        "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J".to_string(),
        "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8".to_string(),
        general_purpose::STANDARD.decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
        general_purpose::STANDARD.decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
        now + 14400
    ).unwrap();

    let req = ncryptf::Request::from(kp.get_secret_key(), token.signature.clone());

    let req_body = req
        .unwrap()
        .encrypt(json.to_string(), ek.get_box_kp().get_public_key())
        .unwrap();
    let astr = general_purpose::STANDARD.encode(req_body.clone());

    let vr = ncryptf::Response::get_version(req_body.clone());
    assert_eq!(vr.unwrap(), 2);

    let auth = match ncryptf::Authorization::from(
        "POST".to_string(),
        "/auth_echo".to_string(),
        token,
        chrono::Utc::now(),
        json.clone().to_string(),
        None,
        Some(2),
    ) {
        Ok(auth) => auth,
        Err(_) => {
            assert!(false);
            panic!("unable to generate auth header")
        }
    };

    let response = client
        .post("/auth_echo")
        .body(astr)
        .header(Header::new("Authorization", auth.get_header()))
        .header(Header::new("Content-Type", "application/vnd.ncryptf+json"))
        .header(Header::new("Accept", "application/vnd.ncryptf+json"))
        .header(Header::new("X-HashId", ek.get_hash_id()))
        .dispatch();

    // We should get an HTTP 200 back
    assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    let bbody = general_purpose::STANDARD.decode(body.clone()).unwrap();
    let r = ncryptf::Response::from(kp.get_secret_key()).unwrap();

    let message = r.decrypt(bbody, None, None);
    assert!(message.is_ok());
    assert_eq!(message.unwrap(), json.to_string());
}

/// This will send an ncryptf encrypted message, and should receive back an ncryptf encrypted response
#[test]
fn test_echo_large_body() {
    let client = setup();

    let ek = get_ek();

    let s = ExampleStruct {
        f: general_purpose::STANDARD.encode(randombytes_buf(64)),
        g: general_purpose::STANDARD.encode(randombytes_buf(64)),
        h: general_purpose::STANDARD.encode(randombytes_buf(64)),
    };
    let json = serde_json::to_string(&s).unwrap();

    let kp = ncryptf::Keypair::new();
    let sk = ncryptf::Signature::new();
    let req = ncryptf::Request::from(kp.get_secret_key(), sk.get_secret_key());

    let req_body = req
        .unwrap()
        .encrypt(json.to_string(), ek.get_box_kp().get_public_key())
        .unwrap();
    let astr = general_purpose::STANDARD.encode(req_body.clone());

    let vr = ncryptf::Response::get_version(req_body.clone());
    assert_eq!(vr.unwrap(), 2);

    let response = client
        .post("/echo2")
        .body(astr)
        .header(Header::new("Content-Type", "application/vnd.ncryptf+json"))
        .header(Header::new("Accept", "application/vnd.ncryptf+json"))
        .header(Header::new("X-HashId", ek.get_hash_id()))
        .dispatch();

    // We should get an HTTP 200 back
    assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    let bbody = general_purpose::STANDARD.decode(body.clone()).unwrap();
    let r = ncryptf::Response::from(kp.get_secret_key()).unwrap();

    let message = r.decrypt(bbody, None, None);
    assert!(message.is_ok());
    assert_eq!(message.unwrap(), json.to_string());
}