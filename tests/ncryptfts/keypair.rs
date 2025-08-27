use dryoc::constants::{CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES};
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
