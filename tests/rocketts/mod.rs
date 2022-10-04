use reqwest::header::HeaderValue;
use rocket::response::content;
use rocket::{local::blocking::Client, http::Header};
use serde::Deserialize;

use rocket::serde::{Serialize, json::Json};

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
        .merge(("log_level", rocket::config::LogLevel::Off));

    let rocket = rocket::custom(config)
        .mount("/", routes![echo]);
    let client = Client::tracked(rocket).unwrap();

    return client
}

#[test]
fn test_echo() {
    let client = setup();

    let json: serde_json::Value = serde_json::from_str(r#"{ "hello": "world"}"#).unwrap();

    let kp = ncryptf::Keypair::new();
    let sk = ncryptf::Signature::new();
    let req = ncryptf::Request::from(
        kp.get_secret_key(),
        sk.get_secret_key()
    );

    let body = req.unwrap().encrypt(json.to_string(), kp.get_public_key()).unwrap();
    let astr = base64::encode(body);

    let response = client.post("/echo")
        .body(astr)
        .header(Header::new("X-Seckey", base64::encode(kp.get_secret_key())))
        .header(Header::new("X-Sig-Seckey", base64::encode(kp.get_secret_key())))
        .header(Header::new("X-Pubkey", base64::encode(kp.get_public_key())))
        .header(Header::new("X-Sig-Pubkey", base64::encode(sk.get_public_key())))
        .dispatch();

    assert_eq!(response.into_string().unwrap(), json.to_string());
}