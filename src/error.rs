use thiserror::Error;

/// Errors that ncryptf may encounter during encrypting and decrypting data - generalized.
#[derive(Error, Debug)]
pub enum NcryptfError {
    #[error("the argument provided `{0}` was did not match the expected type")]
    InvalidArgument(String),
    #[error("the argument provided `{0}` was did not match the expected type")]
    TokenSignatureSize(String),
    #[error("signature could not be generated")]
    SignatureGenerationError,
    #[error("message could not be encrypted")]
    EncryptError,
    #[error("message could not be decrypted")]
    DecryptError
}