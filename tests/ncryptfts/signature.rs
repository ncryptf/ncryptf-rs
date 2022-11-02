use super::cases::{get_date, get_salt, get_test_cases, get_v1_signatures, get_v2_signatures};
use ncryptf::*;

#[test]
fn test_v1_signatures() {
    let cases = get_test_cases();
    let signatures = get_v1_signatures();
    let date = get_date();
    let salt = get_salt();

    for (i, case) in cases.iter().enumerate() {
        let signature = Signature::derive(
            case.method.clone(),
            case.uri.clone(),
            salt.clone(),
            date,
            case.payload.clone(),
            Some(1),
        );
        let expected = signatures.get(i).unwrap().to_owned();
        let e = expected.as_str();
        let s: Vec<&str> = signature.split("\n").collect();
        assert!(s.get(0).unwrap().to_owned().eq(e));
    }
}

#[test]
fn test_v2_signatures() {
    let cases = get_test_cases();
    let signatures = get_v2_signatures();
    let date = get_date();
    let salt = get_salt();

    for (i, case) in cases.iter().enumerate() {
        let signature = Signature::derive(
            case.method.clone(),
            case.uri.clone(),
            salt.clone(),
            date,
            case.payload.clone(),
            Some(2),
        );
        let expected = signatures.get(i).unwrap().to_owned();
        let e = expected.as_str();
        let s: Vec<&str> = signature.split("\n").collect();
        assert!(s.get(0).unwrap().to_owned().eq(e));
    }
}
