use rocket::{local::blocking::Client, http::Header};
use serde::Deserialize;
use redis::Commands;
use rocket::serde::{Serialize, json::Json};
use rocket_db_pools::{Database, deadpool_redis};

/// This is our mock Redis figment
#[derive(Database)]
#[database("cache")]
pub struct RedisDb(deadpool_redis::Pool);

/// A simple test struct
#[derive(Deserialize, Serialize, Clone, Debug)]

struct TestStruct<'r> {
    pub hello: &'r str
}

#[post("/echo", data="<data>")]
fn echo(
    data: ncryptf::rocket::Json<TestStruct>
) -> rocket::serde::json::Json<TestStruct> {
    return Json(data.0);
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

    let body = req.unwrap().encrypt(json.to_string(), ek.get_box_kp().get_public_key()).unwrap();
    let astr = base64::encode(body);

    let response = client.post("/echo")
        .body(astr)
        .header(Header::new("X-HashId", ek.get_hash_id()))
        .dispatch();

    assert_eq!(response.into_string().unwrap(), json.to_string());
}