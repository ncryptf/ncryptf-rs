use dryoc::constants::{CRYPTO_BOX_SECRETKEYBYTES, CRYPTO_BOX_PUBLICKEYBYTES};
use ncryptf::keypair::*;

#[test]
fn test_get_keypair_sk() {
    let kp = Keypair::new();
    assert!(kp.get_secret_key().len() == CRYPTO_BOX_SECRETKEYBYTES);
}

#[test]
fn test_get_keypair_pk() {
    let kp = Keypair::new();
    assert!(kp.get_public_key().len() == CRYPTO_BOX_PUBLICKEYBYTES);
}