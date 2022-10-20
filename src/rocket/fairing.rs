use rocket::{Request, Data};
use rocket::fairing::{Fairing as RocketFairing, Info, Kind};
use rocket::{
    data::{
        Limits,
    }
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
impl RocketFairing for Fairing {
    fn info(&self) -> Info {
        Info {
            name: "Ncryptf Fairing",
            kind: Kind::Request
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, data: &mut Data<'_>) {
        // Global fairing allows us to utilize request guards for both Json<T>, plain text json, and a request guard for authentication
        if let Some(h) = req.headers().get_one("Content-Type") {
            // If the content type is JSON or vnd.ncryptf+json then we will consume data
            // and pre-emptively parse it
            // The request body will be stored in the request cache, and we need to mark that the fairing
            // consumed this data
            //
            // Other content types should work as-is without changes since we're only consuming this for specific content types
            if h.eq(crate::rocket::NCRYPTF_CONTENT_TYPE) || h.eq("application/json") {
                let limit = req.limits().get("json").unwrap_or(Limits::JSON);
                let result = data.get_body(limit.as_u64() as usize).await;
                let vec_data = result.to_vec();
                let string = String::from_utf8(vec_data.clone()).unwrap();
                req.local_cache(|| FairingConsumed(true));

                let version = match req.method().to_string().to_uppercase().as_str() {
                    "GET" => 2,
                    _ => match h {
                        crate::rocket::NCRYPTF_CONTENT_TYPE => {
                            let d = base64::decode(string.clone()).unwrap();
                            match crate::Response::get_version(d) {
                                Ok(version) => version,
                                Err(_) => 1
                            }
                        },
                        _ => 2
                    }
                };

                req.local_cache(|| NcryptfRequestVersion(version));
                req.local_cache(|| NcryptfRawBody(string.clone()));
                match crate::rocket::Json::<serde_json::Value>::deserialize_req_from_string(req, string) {
                    Ok(decrypted) => {
                        req.local_cache(|| return decrypted);
                    },
                    Err(_) => {}
                }
            };
        }
    }
}
