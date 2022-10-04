use libsodium_sys::{
    crypto_box_SECRETKEYBYTES as CRYPTO_BOX_SECRETKEYBYTES,
    crypto_box_PUBLICKEYBYTES as CRYPTO_BOX_PUBLICKEYBYTES
};

use ncryptf::*;

#[test]
fn test_get_keypair_sk() {
    let kp = Keypair::new();
    assert!(kp.get_secret_key().len() == (CRYPTO_BOX_SECRETKEYBYTES as usize));
}

#[test]
fn test_get_keypair_pk() {
    let kp = Keypair::new();
    assert!(kp.get_public_key().len() == (CRYPTO_BOX_PUBLICKEYBYTES as usize));
}