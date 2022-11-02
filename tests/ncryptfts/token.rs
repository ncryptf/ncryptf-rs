use ncryptf::*;

#[test]
fn new_token() {
    let token = Token::new(0);
    assert_eq!(token.ikm.len(), 32);
}
