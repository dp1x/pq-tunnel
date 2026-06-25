use crate::error::CryptoError;
use ml_dsa::{MlDsa65, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::ZeroizeOnDrop;

/// ML-DSA-65 public key size in bytes.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// ML-DSA-65 secret key size in bytes (expanded form).
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
/// ML-DSA-65 signature size in bytes.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

/// ML-DSA-65 public key.
#[derive(Debug, Clone)]
pub struct MlDsaPublicKey(VerifyingKey<MlDsa65>);

/// ML-DSA-65 secret key. Automatically zeroed on drop.
#[derive(Debug, ZeroizeOnDrop)]
pub struct MlDsaSecretKey(SigningKey<MlDsa65>);

/// ML-DSA-65 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlDsaSignature(ml_dsa::Signature<MlDsa65>);

/// ML-DSA-65 keypair.
pub struct MlDsaKeypair {
    pub public: MlDsaPublicKey,
    pub secret: MlDsaSecretKey,
}

impl MlDsaKeypair {
    /// Generate a new ML-DSA-65 keypair using the system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        use ml_dsa::Generate;
        let sk = SigningKey::<MlDsa65>::generate();
        let vk = sk.verifying_key();
        Ok(MlDsaKeypair {
            public: MlDsaPublicKey(vk),
            secret: MlDsaSecretKey(sk),
        })
    }

    /// Sign a message with ML-DSA-65.
    pub fn sign(&self, msg: &[u8]) -> Result<MlDsaSignature, CryptoError> {
        let sig = self.0.sign(msg);
        Ok(MlDsaSignature(sig))
    }

    /// Get the verifying key for this keypair.
    pub fn verifying_key(&self) -> MlDsaPublicKey {
        MlDsaPublicKey(self.0.verifying_key())
    }
}

/// Verify an ML-DSA-65 signature on a message.
pub fn verify(pk: &MlDsaPublicKey, msg: &[u8], sig: &MlDsaSignature) -> Result<bool, CryptoError> {
    match pk.0.verify(msg, &sig.0) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_65_keypair_generation_succeeds() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let pk_bytes = kp.public.0.to_bytes();
        assert_eq!(pk_bytes.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
    }

    #[test]
    fn ml_dsa_65_sign_verify_roundtrip() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let msg = b"hello post-quantum world";
        let sig = kp.sign(msg).expect("sign");
        let valid = verify(&kp.public, msg, &sig).expect("verify");
        assert!(valid, "valid signature must verify");
    }

    #[test]
    fn ml_dsa_65_verify_wrong_message_fails() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let sig = kp.sign(b"correct message").expect("sign");
        let valid = verify(&kp.public, b"wrong message", &sig).expect("verify");
        assert!(!valid, "signature on different message must NOT verify");
    }

    #[test]
    fn ml_dsa_65_verify_wrong_keypair_fails() {
        let kp_a = MlDsaKeypair::generate().expect("keygen");
        let kp_b = MlDsaKeypair::generate().expect("keygen");
        let sig = kp_a.sign(b"some message").expect("sign");
        let valid = verify(&kp_b.public, b"some message", &sig).expect("verify");
        assert!(!valid, "signature from different keypair must NOT verify");
    }

    #[test]
    fn ml_dsa_65_signature_not_all_zeros() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let sig = kp.sign(b"test message").expect("sign");
        let encoded = sig.0.encode();
        assert_ne!(
            encoded.as_slice(),
            &[0u8; ML_DSA_65_SIGNATURE_BYTES],
            "signature must not be all zeros"
        );
    }
}
