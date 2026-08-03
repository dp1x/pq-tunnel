use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("KEM operation failed: {0}")]
    Kem(String),
    #[error("Signature operation failed: {0}")]
    Signature(String),
    #[error("X25519 operation failed: {0}")]
    X25519(String),
    #[error("AEAD operation failed: {0}")]
    Aead(String),
    #[error("KDF operation failed: {0}")]
    Kdf(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Verification failed")]
    VerificationFailed,
}
