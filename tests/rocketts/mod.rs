use rocket::{local::blocking::Client, http::Header};
use serde::Deserialize;
use redis::Commands;
use rocket::serde::{Serialize};

/// A simple test struct
#[derive(Deserialize, Serialize, Clone, Debug)]

struct TestStruct<'r> {
    pub hello: &'r str
}

#[post("/echo", data="<data>")]
fn echo(
    data: ncryptf::rocket::Json<TestStruct>
) -> ncryptf::rocket::Json<TestStruct> {
    return ncryptf::rocket::Json(data.0);
}

fn setup() -> Client{
    let config = rocket::Config::figment()
        .merge(("ident", false))
        .merge(("databases.cache", rocket_db_pools::Config {
            url: format!("redis://127.0.0.1:6379/"),
            min_connections: None,
            max_connections: 1024,
            connect_timeout: 3,
            idle_timeout: None,
        }))
        .merge(("log_level", rocket::config::LogLevel::Off));

    let rocket = rocket::custom(config)
        .mount("/", routes![echo]);

    return match Client::tracked(rocket) {
        Ok(client) => client,
        Err(_error) => {
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

/// This will send an ncryptf encrypted message, and should receive back an ncryptf encrypted response
#[test]
fn test_echo() {
    let client = setup();

    let ek = get_ek();
    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    let kp = ncryptf::Keypair::new();
    let sk = ncryptf::Signature::new();
    let req = ncryptf::Request::from(
        kp.get_secret_key(),
        sk.get_secret_key()
    );

    let req_body = req.unwrap().encrypt(
        json.to_string(),
        ek.get_box_kp().get_public_key()
    ).unwrap();
    let astr = base64::encode(req_body.clone());

    let vr = ncryptf::Response::get_version(req_body.clone());
    assert_eq!(vr.unwrap(), 2);

    let response = client.post("/echo")
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

    let message = r.decrypt(
        bbody,
        None,
        None
    );
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
    let req = ncryptf::Request::from(
        kp.get_secret_key(),
        sk.get_secret_key()
    );

    let body = req.unwrap().encrypt(json.to_string(), ek.get_box_kp().get_public_key()).unwrap();
    let astr = base64::encode(body);

    let response = client.post("/echo")
        .body(astr)
        .header(Header::new("Content-Type", "application/vnd.ncryptf+json"))
        .header(Header::new("Accept", "application/json"))
        .header(Header::new("X-HashId", ek.get_hash_id()))
        .dispatch();

    let body = response.into_string().unwrap();
    assert_eq!(body, json.to_string());
}