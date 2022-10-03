use ncryptf::*;
use super::cases::{get_test_cases, get_date, get_salt, get_token, get_v2_hmac_headers, get_v1_hmac_headers};

#[test]
fn test_v1_hmac() {
    let cases = get_test_cases();
    let hmacs = get_v1_hmac_headers();
    let date = get_date();
    let salt = get_salt();
    let token = get_token();

    for (i, case) in cases.iter().enumerate() {
        let auth = Authorization::from(
            case.method.clone(),
            case.uri.clone(),
            token.clone(),
            date,
            case.payload.clone(),
            Some(salt.clone()),
            Some(1)
        );

        assert!(auth.is_ok());
        let a = auth.unwrap();
        let header = a.get_header();
        let actual = header.as_str();
        let expected = hmacs.get(i).unwrap().as_str();
        assert!(actual.eq(expected));
    }
}

#[test]
fn test_v2_hmac() {
    let cases = get_test_cases();
    let hmacs = get_v2_hmac_headers();
    let date = get_date();
    let salt = get_salt();
    let token = get_token();

    for (i, case) in cases.iter().enumerate() {
        let auth = Authorization::from(
            case.method.clone(),
            case.uri.clone(),
            token.clone(),
            date,
            case.payload.clone(),
            Some(salt.clone()),
            Some(2)
        );

        assert!(auth.is_ok());
        let a = auth.unwrap();
        let header = a.get_header();
        let actual = header.as_str();
        let expected = hmacs.get(i).unwrap().as_str();
        assert!(actual.eq(expected));
    }
}

#[test]
fn test_verify_hmac() {
    let cases = get_test_cases();
    let date = get_date();
    let salt = get_salt();
    let token = get_token();

    for case in cases.iter() {
        let auth = Authorization::from(
            case.method.clone(),
            case.uri.clone(),
            token.clone(),
            date,
            case.payload.clone(),
            Some(salt.clone()),
            Some(2)
        );

        assert!(auth.is_ok());
        let a = auth.unwrap();
        let result = a.verify(a.get_hmac(), 32);
        assert!(result == true);
    }
}