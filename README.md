<div align="center">
  <img src="https://raw.githubusercontent.com/ncryptf/ncryptf-rs/master/logo.png" width="280"/>

  <h1>ncryptf-rs</h1>

  <p>
    <strong><em>Rust</em> bindings for ncryptf</strong>
  </p>
</div>

[![docs.rs](https://img.shields.io/docsrs/ncryptf-rs?style=for-the-badge)](https://docs.rs/ncryptf-rs/0.2.3)
[![Crates.io (recent)](https://img.shields.io/crates/dr/ncryptf-rs?style=for-the-badge)](https://crates.io/crates/ncryptf-rs)

</hr>

The rust ncryptf bindings are intended to be API similar to other language bindings for ease of readability.

## Installing

You can add ncryptf to your project via cargo to your Cargo.toml
```
ncryptf-rs = { git = "github.com/ncryptf/ncryptf-rs" }
```

Ncryptf supports 2 optional features:
- `rocket` for rocket.rs bindings
- `client` which provides a `reqwest` client you can use to interact with ncryptf.

### Exports
ncryptf re-exports a few extra libraries for convenience and necessity.

#### Rocket
Ncryptf uses a modified variant of rocket.rs (0.5.0-rc: see https://github.com/charlesportwoodii/rocket.rs/tree/peek_buffer) to grab the request body to perform authentication with Rocket.rs. It is strongly recommended to have this version of rocket (and other re-exports) stored in a `common` workspace to eliminate the need to add the same cargo dependency in each workspace member.

If you are using rocket.rs `proc_macro` in your `main.rs`, you will still need to import the macro.

```rust
rocket = {  features = ["tls", "secrets", "json"] }
```

### Library Mapping
When using the ncryptf re-exports by default the imported struct names will be namespaced under `ncryptf::<lib>`, which can be confusing to rust-analyzer, and the developer. To make rust-analyzer and the compiler more sane, consider using a `common` workspace that re-exports both ncryptf, rocket, and any other features.

Example:

```
common
  \ - mod.rs
    - ncryptflib.rs
```

In your `mod.rs` or `lib.rs` have the following:
```rust
pub mod ncryptflib
```

Then in your ncryptflib.rs have the following:
```rust
pub use ncryptf::{
    auth,
    client,
    ek_route,
    rocket,
    Authorization,
    Keypair,
    NcryptfError,
    Request,
    Response,
    Token,
    randombytes_buf
};
```

And elsewhere in your code you can then `pub use ncryptflib as ncryptf` to have the standard library available under the normal namespaces without collisions.

## HMAC+HKDF Authentication

HMAC+HKDF Authentication is an Authentication method that allows ensures the request is not tampered with in transit. This provides resiliance not only against network layer manipulation, but also man-in-the-middle attacks.

At a high level, an HMAC signature is created based upon the raw request body, the HTTP method, the URI (with query parameters, if present), and the current date. In addition to ensuring the request cannot be manipulated in transit, it also ensures that the request is timeboxed, effectively preventing replay attacks.

The library itself is made available by importing the following struct:

Supporting API's will return the following payload containing at minimum the following information.

```json
{
    "access_token": "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    "refresh_token": "MA2JX5FXWS57DHW4OIHHQDCJVGS3ZKKFCL7XM4GNOB567I6ER4LQ",
    "ikm": "bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM=",
    "signing": "7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==",
    "expires_at": 1472678411
}
```

With this token you can authorized requests to supporting APIs as follows:

```rust
use ncryptf::*;

match Token::from_json(json) {
  Err(_) => {},
  Ok(token) => {
    let auth = Authorization::from(
      "POST".to_string(),
      "/api/v1/test".to_string(),
      token,
      chrono::offset::Utc::now(),
      None,
      None
    );

    // make a reqwest with Authorization: auth.get_header()
  }
}
```

> Review the crate documentation and other ncryptf libraries for Version 1 header information

## Encrypted Requests & Responses

This library enables clients to establish and trusted encrypted session on top of a TLS layer, while simultaniously (and independently) providing the ability authenticate and identify a client via HMAC+HKDF style authentication.

The rationale for this functionality includes but is not limited to:

1. Necessity for extra layer of security
2. Lack of trust in the network or TLS itself (see https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/)
3. Need to ensure confidentiality of the Initial Key Material (IKM) provided by the server for HMAC+HKDF authentication
4. Need to ensure confidentiality of user submitted credentials to the API for authentication

The primary reason you may want to establish an encrypted session with the API itself is to ensure confidentiality of the IKM to prevent data leakages over untrusted networks to avoid information being exposed in a Cloudflare like incident (or any man-in-the-middle attack). Encrypted sessions enable you to utilize a service like Cloudflare should a memory leak occur again with confidence that the IKM and other secure data would not be exposed.

Review the `test/integration.rs` file for a full example of making requets and encrypting and decrypting responses.

#### Rocket.rs Body Parsing, and Response Emitting
This library provides a Rocket.rs specific implementation to handle incoming encrypted (and by proxy plain-text) JSON requests. Setup for handling this looks as follows:

1. Your server must provide a Redis instance and it must be available to Rocket.

2. Add a `databases.cache` configuration item for a rocket_Db_pools::Config

```rust
 let config = rocket::Config::figment()
    .merge(("databases.cache", rocket_db_pools::Config {
        url: format!("redis://127.0.0.1:6379/"),
        min_connections: None,
        max_connections: 1024,
        connect_timeout: 3,
        idle_timeout: None,
    }))
```

3. Your request will now be able to parse and accept application/json and application/vnd.ncryptf+json by adding a body acceptor for ncryptf::rocket::Json<T>. Both requests and responses can be consumed and emitted this way.

```rust
#[post("/echo", data="<data>")]
fn echo(data: ncryptf::rocket::Json<TestStruct>) -> ncryptf::rocket::Json<TestStruct> {
    return ncryptf::rocket::Json(data.0);
}
```

> `JsonResponse<T>` is also available if you want to return a Ncryptf or plain-text Json response with a status code.

4. For bootstrapping, the library provides a convenience endpoint for generated bootstrapping keys.

```rust
/// Define an actual RedisDb instance
#[derive(Database)]
#[database("cache")]
pub struct RedisDb(deadpool_redis::Pool);

/// Use the provided macro to generate the route.
ek_route!(RedisDb);

/// Attach the dynamic macro route to your request.
let rocket = rocket::custom(config)
      .attach(RedisDb::init())
      .mount("/ncryptf", routes![ncryptf_ek_route]);
```

### Authentication, and Request Verification

Ncryptf also provides functionality for validating a request. The `tests/rocketts` folder contains many examples specific to Rocket, though the approach can be used in any implementation. Ncryptf's request authorization is similar to AWS Signature V2 Authentication in that it:

1. Signs the unencrypted request body for verification server side to ensure the request has not been tampered.
2. Prevents replay attacks.
3. Timeboxes requests to the signed request datetime.

Clients should implement the following to make authorized requests.

1. Generate a token from data provide by an IKM endpoint:
```rust
let token =  ncryptf::Token::from(
        "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J".to_string(),
        "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8".to_string(),
        base64::decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
        base64::decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
        now + 14400
    ).unwrap();
```

2. Create an authorization object for your request.
```rust
 let auth = match ncryptf::Authorization::from(
        "POST".to_string(), /// this must be uppercase
        "/auth_echo".to_string(),
        token,
        Utc::now(),
        json.clone().to_string(),
        None,
        Some(2)
    ) {
        Ok(auth) => auth,
        Err(_) => {
            assert!(false);
            panic!("unable to generate auth header")
        }
    };
```

3. Generate the header and add it to your request.
```rust
let client = reqwest::Client::new();
let res = client
    .post("https://www.ncryptf.com/example")
    .header("Authorization:", auth.get_header())
    .send()
    .await?;
```

If you have enabled the `client` feature, you can also use that to more simply perform requests. See the cargo documentation for more details and examples.

#### Rocket Request Guard

This library additional provides functionality to handle authentication requests fo you, including parsing, and verification with Rocket.rs. Implementation of this can be done as follows.

1. Have your user entity impplement the `ncryptf::rocket::AuthorizationTrait` async_trait.
2. At the end of your User entity implementation, run the following macro to bind the FromRequest Trait.
```rust
ncryptf::auth!(User);
```

3. Your request can now retrieve the User entity as part of a Rocket request guard.
```rust
#[get("/")]
fn auth_echo( _user: User){
    dbg!(_user);
}
```

4. For requests with a body, you can extract the identity and the request data with the data guard:
```rust
#[post("/", data = "<data>")]
fn auth_echo(data = ncryptf::rocket::RequestData<User>){
    let user: User = data.get_identity();
    let s: ncryptf::rocket::Json::<T> = data.get_data();
}
```

You can use this in conjunction with request and response formatting and parsing.

##### Important Notes

This library is doing some _weird_ things to get around several Rocket implementations to appropriately read and parse the request headers and body. As a result, the authorization headers are _only_ parsed and handled if the Content-Type on the request is set to _either_ `application/json` or `application/vnd.ncryptf+json`. Responses are handled via the Accept header, and for both of the aforementioned content types, you must have your Rocket route return an `ncryptf::rocket::Json<T>`, which can appropriately handle both content types.

Furthermore, the ncryptf::rocket::Fairing consumes the DataStream, up to your default JSON limits. If your requests begin to exceed the 8M limit you must extend your limit to capture the full stream as all requests will return a 401 or 403 otherwise.

This library imposes the use of Redis due to the lack of generic caching implementations (like [PSR-6](https://www.php-fig.org/psr/psr-6/)) for Rust. As a result you _must_ provide a functional Redis instance.

### V2 Encrypted Payload

Verison 2 works identical to the version 1 payload, with the exception that all components needed to decrypt the message are bundled within the payload itself, rather than broken out into separate headers. This alleviates developer concerns with needing to manage multiple headers.

The version 2 payload is described as follows. Each component is concatanated together.

| Segment | Length |
|---------|--------|
| 4 byte header `DE259002` in binary format | 4 BYTES |
| Nonce | 24 BYTES |
| The public key associated to the private key | 32 BYTES |
| Encrypted Body | X BYTES |
| Signature Public Key | 32 BYTES |
| Signature or raw request body | 64 BYTES |
| Checksum of prior elements concatonated together | 64 BYTES |
