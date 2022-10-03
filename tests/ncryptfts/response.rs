use ncryptf::Response;
use ncryptf::Request;
use super::cases::{get_expected_cipher,get_expected_v2_cipher, CData};

#[test]
fn test_v1_version() {
    match Response::get_version(get_expected_cipher()) {
        Ok(result) => match result {
            1 => {
                assert!(true)
            },
            _ => {
                assert!(false)
            }
        },
        Err(_) => {
            assert!(false)
        }
    };
}

#[test]
fn test_v2_version() {
    match Response::get_version(get_expected_v2_cipher()) {
        Ok(result) => match result {
            2 => {
                assert!(true)
            },
            _ => {
                assert!(false)
            }
        },
        Err(_) => {
            assert!(false == true)
        }
    };
}

#[test]
fn test_public_key_extraction() {
    match Response::get_public_key_from_response(get_expected_v2_cipher()) {
        Ok(result) => {
            let c = CData::init();
            let cmp = constant_time_eq::constant_time_eq(&result, &c.client_kp_public.clone());
            assert!(cmp);
        },
        Err(_) => {
            assert!(false)
        }
    };
}

#[test]
fn test_sign_and_verify() {
    let c = CData::init();
     match Request::from(c.client_kp_secret, c.signature_kp_secret) {
        Ok(request) => {
            let signature = request.sign("".to_string());

            assert!(Response::is_signature_valid(
                "".to_string(),
                signature.unwrap(),
                c.signature_kp_public).unwrap());
        },
        _ => {
            assert!(false);
        }
    };
}

#[test]
#[ignore]
fn test_signature_extraction() {
    unimplemented!();
}