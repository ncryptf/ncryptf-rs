use ncryptf::{ek_route, randombytes_buf, rocket::ExportableEncryptionKeyData};
use redis::Commands;
use rocket::{http::Header, local::blocking::Client, serde::Serialize, fairing::AdHoc};
use serde::Deserialize;
use ncryptf::rocket::Fairing as NcryptfFairing;
use rocket_db_pools::{deadpool_redis, Database};

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
        _f: rocket_db_pools::figment::Figment,
    ) -> Result<ncryptf::Token, ncryptf::rocket::TokenError> {
        let now = chrono::Utc::now().timestamp();

        let token =  ncryptf::Token::from(
            "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J".to_string(),
            "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8".to_string(),
            base64::decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
            base64::decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
            now + 14400
        ).unwrap();

        return Ok(token);
    }

    /// Returns a static user from an authorization token
    async fn get_user_from_token(
        _token: ncryptf::Token,
        _f: rocket_db_pools::figment::Figment,
    ) -> Result<Box<Self>, ncryptf::rocket::TokenError> {
        return Ok(Box::new(User { id: 1 }));
    }
}

ncryptf::auth!(User);

#[derive(Database)]
#[database("cache")]
pub struct RedisDb(deadpool_redis::Pool);

/// A simple test struct
#[derive(Deserialize, Serialize, Clone, Debug)]
struct TestStruct<'r> {
    pub hello: &'r str,
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
    data: ncryptf::rocket::Json<TestStruct>,
    _user: User, // Satisfying the reqest guard is sufficient to verify the request can be parsed
) -> ncryptf::rocket::Json<TestStruct> {
    return ncryptf::rocket::Json(data.0);
}

/// Setup helper function
fn setup() -> Client {
    let config = rocket::Config::figment()
        .merge(("ident", false))
        .merge((
            "databases.cache",
            rocket_db_pools::Config {
                url: format!("redis://127.0.0.1:6379/"),
                min_connections: None,
                max_connections: 1024,
                connect_timeout: 3,
                idle_timeout: None,
            },
        ))
        .merge((
            "databases.cache2",
            rocket_db_pools::Config {
                url: format!("redis://127.0.0.1:6379/"),
                min_connections: None,
                max_connections: 1024,
                connect_timeout: 3,
                idle_timeout: None,
            },
        ))
        .merge(("log_level", rocket::config::LogLevel::Debug));

    ek_route!(RedisDb);

    let rocket = rocket::custom(config)
        .attach(NcryptfFairing)
        .attach(RedisDb::init())
        .mount("/", routes![echo, auth_echo, echo2])
        .mount("/ncryptf", routes![ncryptf_ek_route])
        .attach(AdHoc::on_request("transforms", |_req, data| Box::pin(async {
            data.chain_inspect(move |_| {
                println!("chain inspect occured");
            });
        })));
    
    return match Client::untracked(rocket) {
        Ok(client) => client,
        Err(_error) => {
            dbg!(_error);
            panic!("Failed to create client");
        }
    };
}

fn get_ek() -> ncryptf::rocket::EncryptionKey {
    let rdb = "redis://127.0.0.1/".to_string();
    // Create a new client
    let client = match redis::Client::open(rdb) {
        Ok(client) => client,
        Err(_error) => {
            panic!("Client couldn't be created");
        }
    };

    // Retrieve the connection string
    let mut conn: redis::Connection = match client.get_connection() {
        Ok(conn) => conn,
        Err(_error) => {
            panic!("Could not open Redis database.");
        }
    };

    let ek = ncryptf::rocket::EncryptionKey::new(false);
    let d = serde_json::to_string(&ek).unwrap();

    match conn.set(ek.get_hash_id(), d) {
        Ok(r) => r,
        Err(_) => {
            panic!("Could not set database value.");
        }
    };

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
            let signature = base64::decode(json.signature);
            let public = base64::decode(json.public);
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
    let astr = base64::encode(req_body.clone());

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
    let bbody = base64::decode(body.clone()).unwrap();
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
    let astr = base64::encode(body.clone());

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
        .header(Header::new("X-PubKey", base64::encode(kp.get_public_key())))
        .dispatch();

    // We should get an HTTP 200 back
    assert_eq!(response.status().code, 200);
    let body = response.into_string().unwrap();
    let bbody = base64::decode(body.clone()).unwrap();
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
        base64::decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
        base64::decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
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
        base64::decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
        base64::decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
        now + 14400
    ).unwrap();

    let req = ncryptf::Request::from(kp.get_secret_key(), token.signature.clone());

    let req_body = req
        .unwrap()
        .encrypt(json.to_string(), ek.get_box_kp().get_public_key())
        .unwrap();
    let astr = base64::encode(req_body.clone());

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
    let bbody = base64::decode(body.clone()).unwrap();
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
        f: base64::encode(randombytes_buf(64)),
        g: base64::encode(randombytes_buf(64)),
        h: base64::encode(randombytes_buf(64)),
    };
    let json = serde_json::to_string(&s).unwrap();

    let kp = ncryptf::Keypair::new();
    let sk = ncryptf::Signature::new();
    let req = ncryptf::Request::from(kp.get_secret_key(), sk.get_secret_key());

    let req_body = req
        .unwrap()
        .encrypt(json.to_string(), ek.get_box_kp().get_public_key())
        .unwrap();
    let astr = base64::encode(req_body.clone());

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
    let bbody = base64::decode(body.clone()).unwrap();
    let r = ncryptf::Response::from(kp.get_secret_key()).unwrap();

    let message = r.decrypt(bbody, None, None);
    assert!(message.is_ok());
    assert_eq!(message.unwrap(), json.to_string());
}


use parking_lot::Mutex;
use ubyte::ToByteUnit;
use std::sync::Arc;
use rocket::http::Method;
use rocket::{route, Route, Data, Response, Request};
use rocket::tokio::io::ReadBuf;

#[test]
fn test_transform_series() {
    fn handler<'r>(_: &'r Request<'_>, data: Data<'r>) -> route::BoxFuture<'r> {
        Box::pin(async move {
            data.open(128.bytes()).stream_to(rocket::tokio::io::sink()).await.expect("read ok");
            route::Outcome::Success(Response::new())
        })
    }

    #[post("/echo", data = "<data>")]
    fn echo(data: String) -> String {
        String::from("Hello, World")
    }

    let raw_data: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let rocket = crate::rocket::build()
        .manage(raw_data.clone())
        .mount("/", routes![echo])
        .mount("/", vec![Route::new(Method::Post, "/", handler)])
        .attach(AdHoc::on_request("transforms", |req, data| Box::pin(async {
            let raw_data = req.rocket().state::<Arc<Mutex<Vec<u8>>>>().cloned().unwrap();
            data.chain_inspect(move |bytes| { *raw_data.lock() = bytes.to_vec(); 
            
                println!("chain inspect occured");
            });
        })));

    // Make sure nothing has happened yet.
    assert!(raw_data.lock().is_empty());

    // Check that nothing happens if the data isn't read.
    let client = Client::untracked(rocket).unwrap();
    client.get("/").body("Hello, world!").dispatch();
    assert!(raw_data.lock().is_empty());

    // Check inspect + hash + inspect + inspect.
    client.post("/").body("Hello, world!").dispatch();
    assert_eq!(raw_data.lock().as_slice(), "Hello, world!".as_bytes());

    // Check inspect + hash + inspect + inspect, round 2.
    let string = "Rocket, Rocket, where art thee? Oh, tis in the sky, I see!";
    client.post("/").body(string).dispatch();
    assert_eq!(raw_data.lock().as_slice(), string.as_bytes());

    let s2 = "Hello, World2";
    client.post("/echo").body(s2).dispatch();
    assert_eq!(raw_data.lock().as_slice(), s2.as_bytes());
}