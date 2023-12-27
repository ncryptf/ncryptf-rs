use std::{sync::Arc, pin::Pin};
use rocket::{
    fairing::{Fairing as rocketairing, Info, Kind},
    Data, Request, tokio::io::AsyncRead,
};

/// Indicates in request.local_cache if the fairing consumed the DataStream or not
pub struct FairingConsumed(pub bool);

/// Cache Ncryptf Version of the reuqest
pub struct NcryptfRequestVersion(pub i32);

/// Cached Ncryptf raw body
pub struct NcryptfRawBody(pub String);

/// Ncryptf Fairing necessary for implemeting AuthorizationTrait
pub struct Fairing;

#[rocket::async_trait]
impl rocketairing for Fairing {
    fn info(&self) -> Info {
        Info {
            name: "Ncryptf Fairing",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>,  data: &mut Data<'_>) {
        // Global fairing allows us to utilize request guards for both Json<T>, plain text json, and a request guard for authentication
        if let Some(h) = req.headers().get_one("Content-Type") {
            // If the content type is JSON or vnd.ncryptf+json then we will consume data
            // and pre-emptively parse it
            // The request body will be stored in the request cache, and we need to mark that the fairing
            // consumed this data
            //
            // Other content types should work as-is without changes since we're only consuming this for specific content types
            if h.eq(crate::rocket::NCRYPTF_CONTENT_TYPE) || h.eq("application/json") {
                // This should work in Rocket 0.6...
                let raw_body = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
                let raw_body_cp = raw_body.clone();
                data.chain_inspect(move |bytes| {
                    *raw_body.lock().unwrap() = bytes.to_vec()
                });

                let string = match String::from_utf8(raw_body_cp.lock().unwrap().to_vec()) {
                    Ok(s) => {
                        req.local_cache(|| FairingConsumed(true));
                        s
                    },
                    Err(error) => String::from(error.to_string())
                };

                println!("Captured String: {:?}", string);


                let version = match req.method().to_string().to_uppercase().as_str() {
                    "GET" => 2,
                    _ => match h {
                        crate::rocket::NCRYPTF_CONTENT_TYPE => {
                            let d = match base64::decode(string.clone()) {
                                Ok(d) => d,
                                Err(_error) => {
                                    let d: Vec<u8> = vec![0];
                                    d
                                }
                            };

                            match crate::Response::get_version(d) {
                                Ok(version) => version,
                                Err(_) => 1,
                            }
                        },
                        _ => 2,
                    },
                };

                req.local_cache(|| NcryptfRequestVersion(version));
                req.local_cache(|| NcryptfRawBody(string.clone()));
                match crate::rocket::Json::<serde_json::Value>::deserialize_req_from_string(
                    req, string,
                ) {
                    Ok(decrypted) => {
                        req.local_cache(|| return decrypted);
                    }
                    Err(_) => {}
                }
            };
        }
    }
}
