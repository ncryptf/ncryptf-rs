use rocket::{Request, Data};
use rocket::fairing::{Fairing as RocketFairing, Info, Kind};
use rocket::{
    data::{
        Limits,
    }
};

pub struct FairingConsumed(pub bool);

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
        match req.headers().get_one("Content-Type") {
            Some(h) => {
                // If the content type is JSON or vnd.ncryptf+json then we will consume data
                // and pre-emptively parse it
                // The request body will be stored in the request cache, and we need to mark that the fairing
                // consumed this data
                //
                // Other content types should work as-is without changes since we're only consuming this for specific content types
                if h.eq(crate::rocket::NCRYPTF_CONTENT_TYPE) || h.eq("json") {
                    // .open won't let us read but we can "peek" the full length of the request
                    let limit = req.limits().get("json").unwrap_or(Limits::JSON);
                    let ds = data.peek(limit.as_u64() as usize).await;
                    let string = String::from_utf8(ds.to_vec()).unwrap();

                    req.local_cache(|| FairingConsumed(true));
                    let _ = crate::rocket::Json::<serde_json::Value>::deserialize_req_from_string(req, string);
                }
            },
            _ => return
        };
    }
}
