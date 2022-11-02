/// Returns len random bytes a Vec<u8> using libsodium
pub fn randombytes_buf(len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    unsafe { libsodium_sys::randombytes_buf(bytes.as_mut_ptr().cast(), len) };
    return bytes.to_owned();
}
