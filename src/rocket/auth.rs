use std::time::{SystemTime, UNIX_EPOCH};

use rocket::{request::{self, Request, FromRequest}, http::Status, outcome::Outcome};

#[derive(Clone, Debug)]
pub enum TokenError {
    InvalidToken
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for crate::Token {
    type Error = TokenError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {

        dbg!(req.local_cache(|| return "".to_string()));

        let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

        let token =  crate::Token::from(
            "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J".to_string(),
            "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8".to_string(),
            base64::decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
            base64::decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
            now + 14400
        ).unwrap();

        return Outcome::Success(token);
    }
}