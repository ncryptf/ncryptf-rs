use thiserror::Error;

#[derive(Error, Debug)]
pub enum NcryptfError {
    #[error("the argument provided `{0}` was did not match the expected type")]
    InvalidArgument(String),
    #[error("the argument provided `{0}` was did not match the expected type")]
    TokenSignatureSize(String)
}