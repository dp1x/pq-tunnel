use crate::error::CryptoError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroize;

pub const AEAD_KEY_BYTES: usize = 32;
pub const AEAD_NONCE_BYTES: usize = 12;
pub const AEAD_TAG_BYTES: usize = 16;

#[derive(Clone)]
pub struct AeadKey(pub(crate) [u8; AEAD_KEY_BYTES]);

impl AeadKey {
    pub fn from_bytes(bytes: [u8; AEAD_KEY_BYTES]) -> Self {
        AeadKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; AEAD_KEY_BYTES] {
        &self.0
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AeadKey([REDACTED])")
    }
}

#[derive(Clone)]
pub struct AeadNonce(pub(crate) [u8; AEAD_NONCE_BYTES]);

impl AeadNonce {
    pub fn from_bytes(bytes: [u8; AEAD_NONCE_BYTES]) -> Self {
        AeadNonce(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; AEAD_NONCE_BYTES] {
        &self.0
    }
}

impl Drop for AeadNonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for AeadNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AeadNonce([REDACTED])")
    }
}

pub fn encrypt(
    key: &AeadKey,
    nonce: &AeadNonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::Aead(format!("invalid key: {}", e)))?;
    let n = Nonce::from_slice(nonce.as_bytes());
    cipher
        .encrypt(
            n,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Aead(format!("encryption failed: {}", e)))
}

pub fn decrypt(
    key: &AeadKey,
    nonce: &AeadNonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::Aead(format!("invalid key: {}", e)))?;
    let n = Nonce::from_slice(nonce.as_bytes());
    cipher
        .decrypt(
            n,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Aead(format!("decryption failed: {}", e)))
}

pub fn encrypt_no_aad(
    key: &AeadKey,
    nonce: &AeadNonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    encrypt(key, nonce, plaintext, &[])
}

pub fn decrypt_no_aad(
    key: &AeadKey,
    nonce: &AeadNonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    decrypt(key, nonce, ciphertext, &[])
}

pub fn random_nonce() -> AeadNonce {
    let mut n = [0u8; AEAD_NONCE_BYTES];
    getrandom::fill(&mut n).expect("getrandom for nonce");
    AeadNonce(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_encrypt_decrypt_roundtrip() {
        let key = AeadKey::from_bytes([0xABu8; 32]);
        let nonce = AeadNonce::from_bytes([0x42u8; 12]);
        let plaintext = b"hello tunnel";
        let ct = encrypt(&key, &nonce, plaintext, b"aad").expect("encrypt");
        assert_eq!(ct.len(), plaintext.len() + AEAD_TAG_BYTES);
        let pt = decrypt(&key, &nonce, &ct, b"aad").expect("decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn aead_rejects_wrong_aad() {
        let key = AeadKey::from_bytes([0xABu8; 32]);
        let nonce = AeadNonce::from_bytes([0x42u8; 12]);
        let plaintext = b"hello tunnel";
        let ct = encrypt(&key, &nonce, plaintext, b"correct_aad").expect("encrypt");
        let result = decrypt(&key, &nonce, &ct, b"wrong_aad");
        assert!(result.is_err(), "wrong AAD must fail decryption");
    }

    #[test]
    fn aead_rejects_wrong_key() {
        let key1 = AeadKey::from_bytes([0xABu8; 32]);
        let key2 = AeadKey::from_bytes([0xCDu8; 32]);
        let nonce = AeadNonce::from_bytes([0x42u8; 12]);
        let plaintext = b"hello tunnel";
        let ct = encrypt(&key1, &nonce, plaintext, b"").expect("encrypt");
        let result = decrypt(&key2, &nonce, &ct, b"");
        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let key = AeadKey::from_bytes([0xABu8; 32]);
        let nonce = AeadNonce::from_bytes([0x42u8; 12]);
        let plaintext = b"hello tunnel";
        let mut ct = encrypt(&key, &nonce, plaintext, b"").expect("encrypt");
        ct[0] ^= 0xFF;
        let result = decrypt(&key, &nonce, &ct, b"");
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }

    #[test]
    fn aead_same_plaintext_different_nonce() {
        let key = AeadKey::from_bytes([0xABu8; 32]);
        let nonce1 = AeadNonce::from_bytes([0x11u8; 12]);
        let nonce2 = AeadNonce::from_bytes([0x22u8; 12]);
        let plaintext = b"same plaintext";
        let ct1 = encrypt(&key, &nonce1, plaintext, b"").expect("encrypt1");
        let ct2 = encrypt(&key, &nonce2, plaintext, b"").expect("encrypt2");
        assert_ne!(
            &ct1[..plaintext.len()],
            &ct2[..plaintext.len()],
            "same plaintext + different nonce must produce different ciphertext"
        );
    }

    #[test]
    fn aead_no_aad_roundtrip() {
        let key = AeadKey::from_bytes([0x42u8; 32]);
        let nonce = AeadNonce::from_bytes([0x11u8; 12]);
        let plaintext = b"data packet";
        let ct = encrypt_no_aad(&key, &nonce, plaintext).expect("encrypt");
        assert_eq!(ct.len(), plaintext.len() + AEAD_TAG_BYTES);
        let pt = decrypt_no_aad(&key, &nonce, &ct).expect("decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn aead_tag_size_is_16_bytes() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = AeadNonce::from_bytes([0u8; 12]);
        let ct = encrypt_no_aad(&key, &nonce, b"x").expect("encrypt");
        assert_eq!(ct.len(), 1 + AEAD_TAG_BYTES);
    }

    #[test]
    fn aead_encrypt_does_not_mutate_input() {
        let key = AeadKey::from_bytes([0xABu8; 32]);
        let nonce = AeadNonce::from_bytes([0x42u8; 12]);
        let plaintext = b"unmutated";
        let pt_copy = plaintext.to_vec();
        let _ = encrypt(&key, &nonce, &pt_copy, b"").expect("encrypt");
        assert_eq!(&pt_copy, &plaintext);
    }
}
