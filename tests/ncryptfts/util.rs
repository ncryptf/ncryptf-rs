use ncryptf::randombytes_buf;

#[test]
fn test_randombytes() {
    let bytes = randombytes_buf(32);
    assert_eq!(bytes.len(), 32);
}
