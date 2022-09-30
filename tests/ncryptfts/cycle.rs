use ncryptf::request::Request;
use ncryptf::response::Response;

use super::cases::{CData, get_payload, get_expected_v2_cipher};

#[test]
fn test_v2_encrypt_decrypt() {
    let c = CData::init();
     match Request::from(c.client_kp_secret, c.signature_kp_secret) {
        Ok(mut request) => {
            match request.encrypt_with_nonce(
                get_payload(),
                c.server_kp_public,
                Some(c.nonce.clone()),
                Some(2)
            ) {
                Ok(cipher) => {
                    match Response::from(c.server_kp_secret) {
                        Ok(response) => {
                            match response.decrypt(cipher, None, None) {
                                Ok(text) => {
                                    assert_eq!(text, get_payload());
                                },
                                _ => assert!(false)
                            }
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };
        },
        _ => {
            assert!(false);
        }
    };

}