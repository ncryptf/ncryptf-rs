use std::time::{SystemTime, UNIX_EPOCH};
use base64;
use chrono::Utc;
use chrono::TimeZone;
use ncryptf::token::Token;
#[derive(Debug, Clone)]
pub struct TestCase {
    pub method: String,
    pub uri: String,
    pub payload: String
}

pub fn get_date() -> chrono::DateTime<chrono::offset::Utc> {
    return Utc.timestamp(1533310068, 0);
}

pub fn get_salt() -> Vec<u8> {
    return base64::decode("efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=").ok().unwrap();
}

pub fn get_test_cases() -> Vec<TestCase> {
    return [
        TestCase {method: "GET".to_string(), uri: "/api/v1/test".to_string(), payload: "".to_string()},
        TestCase {method: "GET".to_string(), uri: "/api/v1/test?foo=bar".to_string(), payload: "".to_string()},
        TestCase {method: "GET".to_string(), uri: "/api/v1/test?foo=bar&a[a]=1".to_string(), payload: "".to_string()},
        TestCase {method: "POST".to_string(), uri: "/api/v1/test".to_string(), payload: "{\"foo\":\"bar\"}".to_string()},
        TestCase {method: "POST".to_string(), uri: "/api/v1/test".to_string(), payload: "{\"foo\":1}".to_string()},
        TestCase {method: "POST".to_string(), uri: "/api/v1/test".to_string(), payload: "{\"foo\":false}".to_string()},
        TestCase {method: "POST".to_string(), uri: "/api/v1/test".to_string(), payload: "{\"foo\":1.023}".to_string()},
        TestCase {method: "DELETE".to_string(), uri: "/api/v1/test".to_string(), payload: "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [0.0, 1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}".to_string()},
        TestCase {method: "DELETE".to_string(), uri: "/api/v1/test?foo=bar".to_string(), payload: "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [0.0, 1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}".to_string()},
    ].to_vec();
}

pub fn get_v1_signatures() -> Vec<String> {
    return [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        "7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b".to_string(),
        "37a76343c8e3c695feeaadfe52329673ff129c65f99f55ae6056c9254f4c481d".to_string(),
        "4da787ba25545ca80765298be5676370dae5db4892e9ff59511a2c13ea20c7f5".to_string(),
        "9782504e91ad436a9cf456454922cfe143163a2c1361882b0dffb754638b5050".to_string(),
        "69b3df79d454e1fdd375e53612c61e5e0e5deaa9e98e5746296a52c6f2bad9bb".to_string(),
        "69b3df79d454e1fdd375e53612c61e5e0e5deaa9e98e5746296a52c6f2bad9bb".to_string()
    ].map(String::from).to_vec();
}

pub fn get_v2_signatures() -> Vec<String> {
    return [
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==".to_string(),
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==".to_string(),
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==".to_string(),
        "cH3ZMCv5+dQqFKxuSSRmVaRvAiu3QQJ75gQAE1Q+M3ZI8GcNKdHOtl86JesbP31v/m7uHsAkbDgz0BsfBHKPIA==".to_string(),
        "ZZW9zm1I0rZLr7++giav+lQ59b7AoVltfqK03MJsvAKr7qPHeda0qz/nGU3pqtZgJ3VozweIrORZWIspweJc1g==".to_string(),
        "Mapt8KeGXDIFFPgs7YplHmykBfm9PkD4QHq0J+ozsdtpFcX5mB8xtj0SfVsxWeWLt7Ydm3CjOqHfOh3v/wMC4A==".to_string(),
        "EWE0+YqAyzIr0vbSVXHSpcn/mnWr0I2oAmJ9Med2jVW9p5NbzxbDc4AhEbTT4ha9f7RQFJI0ddY1SzK8fK8LpQ==".to_string(),
        "NTNNxhPRBFJd6g5QShHG44SwuHzWN4bVsKGe1vSXOr/ugRadeA4xiLMmnWSIsql/kILH1ez/asd3Y7Yv1BOqYQ==".to_string(),
        "NTNNxhPRBFJd6g5QShHG44SwuHzWN4bVsKGe1vSXOr/ugRadeA4xiLMmnWSIsql/kILH1ez/asd3Y7Yv1BOqYQ==".to_string()
    ].map(String::from).to_vec();
}

pub fn get_token() -> Token {
    let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

    return Token::from(
        "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J".to_string(),
        "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8".to_string(),
        base64::decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=").unwrap().to_vec(),
        base64::decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==").unwrap().to_vec(),
        now + 14400
    ).unwrap();
}