pub mod aead;
pub mod error;
pub mod kdf;
pub mod kem;
pub mod signature;
pub mod transcript;

/// Known-answer test vectors (M5.1). `#[cfg(test)]`-only: never compiled into
/// production builds, so no production API exists solely to support the KATs
/// (D21). Vectors are quoted verbatim from RFC 8439/5869/7748 and from
/// Wycheproof `testvectors_v1`.
#[cfg(test)]
pub mod kat_vectors;

/// Classical X25519 key exchange.
///
/// X25519 is the classical leg of Tunnel's hybrid key-establishment profile
/// (ML-KEM-768 + X25519, both ephemeral �?" DESIGN_DECISIONS D13). It is
/// deprecated as a *sole* mechanism: X25519 alone provides no post-quantum
/// protection and must never be used as the only key-establishment component.
pub mod classical;

pub use aead::{
    AEAD_KEY_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES, AeadKey, AeadNonce, decrypt, decrypt_no_aad,
    encrypt, encrypt_no_aad, random_nonce,
};
pub use error::CryptoError;
pub use kdf::{
    KDF_SALT_BYTES, MasterSecret, build_session_nonce, compute_client_finished,
    derive_client_to_server_key, derive_finished_key, derive_handshake_init_key,
    derive_handshake_init_nonce, derive_master_secret, derive_master_secret_v2,
    derive_nonce_prefix_c2s, derive_nonce_prefix_s2c, derive_server_to_client_key, kdf_derive,
};
pub use kem::{
    ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES, ML_KEM_768_SECRET_KEY_BYTES,
    ML_KEM_768_SHARED_SECRET_BYTES, MlKemCiphertext, MlKemKeypair, MlKemPublicKey, MlKemSecretKey,
    MlKemSharedSecret, decapsulate, encapsulate,
};
pub use signature::{
    ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, verify,
};
pub use transcript::{Transcript, sha256};

pub use classical::{X25519Keypair, X25519PublicKey, X25519SecretKey};
