/// Returns len random bytes a Vec<u8> using dryoc
pub fn randombytes_buf(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    dryoc::rng::copy_randombytes(&mut bytes);
    bytes
}
