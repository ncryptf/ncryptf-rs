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

pub fn get_v1_hmac_headers() -> Vec<String> {
    return [
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,26TEEe+mUjhYmgXRcy4nL+awe6ksdahhjzujFo1B4UM=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,sdDSnLvddq6IBTv0H/o4hY4u9GFzLrgP5fL0NqFxz5A=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,1g+EfJQ2JnxxVeUfUINhweftK2gCqYpMtPuJ+rc6P4A=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,Tb4/56uZ7FDtBHAbwCgYFirrXW0uhkSRFjLOZYrpHdE=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,bxbitvadJE2APYi3rid3e5SM99X2urjl1vefvZeFGeI=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,O9BUjVPYZ4zE7rlaE2C5Qt0pAa8orAJhLbxIIxV66TU=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,38TB5rfmBJ+NhxQn1lWCeG4aseFuXUthwNz61WlsjIQ=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,2wECEgRUOq1B6v8p9t1qHQME53HQfAMpjS38qI6S01M=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,ddzN/izj4XNxKx/CkZAw9uB0SXDNmxPo1zC0wgQIcrM=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=".to_string(),
    ].map(String::from).to_vec();
}

pub fn get_v2_hmac_headers() -> Vec<String> {
    return [
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiaTZHQzFtZUtWQ3VhQTYzXC9FcXBUazVYZ2VEY3pvY0ErMWxUdE5STWhLcDQ9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==".to_string(),
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiVFErejZKbzYyeDBLV0lKcjhZSzE1c1J5ZjExc09cL3daVFFhMGRBa0toT1k9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==".to_string(),
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiXC9cL21uOExkTnhIU2hlVXkwVVVLd0VGRUxwVituVVNid2l6Y3BZUkNOM29ZPSIsInNhbHQiOiJlZkVZXC9JSmRBYmk0NzRUdFFDQ2pqMnkxRkdCNEJGRlBwYkhtXC8xUXRweUk9IiwidiI6Mn0=".to_string(),
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiY3I1TCsxR0hGeEdIVXV2VFJjVHdCNmJzKzk5ZmNEUDhWZTk2R29NTERtaz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9".to_string(),
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoieUVSUWpsWFgyU29CTVVpeEsydU9LeUZMSDZWeDdob2E4MHdZOXJiRDlucz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9".to_string(),
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiaUx0c0poT25hWkxIbTgrYU9SWTBzUlFrRjdnVmRxaVFKTzVcL0NYRUQrck09Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==".to_string(),
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiS0xlWkVJK1R3Qk16ZXBxTGNqXC91anFYcVhEZUFhUndvbmxPcU9XYjZjT2M9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==".to_string(),
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoidElsRW1vdDNGNm50UzdMRTdWa21BN0hNRVFpenBndVZXZm9MUXY2bnlWbz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9".to_string(),
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiNGlNUDZUMGFVekpwbHczK2IzQUxnMGZBVEtxcHdFUHZrNGcyRDN1bjdxVT0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9".to_string(),
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

pub fn get_expected_cipher() -> Vec<u8> {
    return base64::decode("1odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0=").unwrap();
}

pub fn get_expected_signature() -> Vec<u8> {
    return base64::decode("dcvJclMxEx7pcW/jeVm0mFHGxVksY6h0/vNkZTfVf+wftofnP+yDFdrNs5TtZ+FQ0KEOm6mm9XUMXavLaU9yDg==").unwrap();
}

pub fn get_expected_v2_cipher() -> Vec<u8> {
    return base64::decode("3iWQAm7pUZyrfwb8J8IgjAS73UTOfsjRT9/FLTo569CkMuhiesfnkGvsDcHR3o2aPL2OVTcmWOTX8AY11odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0i42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsXXLyXJTMRMe6XFv43lZtJhRxsVZLGOodP7zZGU31X/sH7aH5z/sgxXazbOU7WfhUNChDpuppvV1DF2ry2lPcg4SwqYwa53inoY2+eCPP4Hkp/PKhSOEMFlWV+dlQirn6GGf5RQSsQ7ti/QCvi/BRIhb3ZHiPptZJZIbYwqIpvYu").unwrap();
}

pub fn get_payload() -> String {
    return r#"{
        "foo": "bar",
        "test": {
            "true": false,
            "zero": 0.0,
            "a": 1,
            "b": 3.14,
            "nil": null,
            "arr": [
                "a", "b", "c", "d"
            ]
        }
    }"#.to_string();
}

pub struct CData {
    pub client_kp_secret: Vec<u8>,
    pub client_kp_public: Vec<u8>,
    pub server_kp_secret: Vec<u8>,
    pub server_kp_public: Vec<u8>,
    pub signature_kp_secret: Vec<u8>,
    pub signature_kp_public: Vec<u8>,
    pub nonce: Vec<u8>
}

impl CData {
    pub fn init() -> Self {
        return Self {
            client_kp_secret: base64::decode("bvV/vnfB43spmprI8aBK/Fd8xxSBlx7EhuxfxxTVI2o=").unwrap(),
            client_kp_public: base64::decode("Ojnr0KQy6GJ6x+eQa+wNwdHejZo8vY5VNyZY5NfwBjU=").unwrap(),
            server_kp_secret: base64::decode("gH1+ileX1W5fMeOWue8HxdREnK04u72ybxCQgivWoZ4=").unwrap(),
            server_kp_public: base64::decode("YU74X2OqHujLVDH9wgEHscD5eyiLPvcugRUZG6R3BB8=").unwrap(),
            signature_kp_secret: base64::decode("9wdUWlSW2ZQB6ImeUZ5rVqcW+mgQncN1Cr5D2YvFdvEi42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsQ==").unwrap(),
            signature_kp_public: base64::decode("IuNjSiv+ueMxrcU0jnDRzxMLRQM9AOJNIcJSBaKWRLE=").unwrap(),
            nonce: base64::decode("bulRnKt/BvwnwiCMBLvdRM5+yNFP38Ut").unwrap()
        }
    }
}