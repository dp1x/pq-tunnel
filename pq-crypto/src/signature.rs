use crate::error::CryptoError;
use kem::KeyExport;
use ml_dsa::{Keypair, MlDsa65 as MlDsaParams, Generate, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::ZeroizeOnDrop;

pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

#[derive(Debug, Clone)]
pub struct MlDsaPublicKey(pub(crate) VerifyingKey<MlDsaParams>);

#[derive(Debug, ZeroizeOnDrop)]
pub struct MlDsaSecretKey(pub(crate) SigningKey<MlDsaParams>);

#[derive(Debug, Clone, PartialEq)]
pub struct MlDsaSignature(pub(crate) ml_dsa::Signature<MlDsaParams>);

pub struct MlDsaKeypair {
    pub public: MlDsaPublicKey,
    pub secret: MlDsaSecretKey,
}

impl MlDsaKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        let sk = SigningKey::<MlDsaParams>::generate();
        let vk = sk.verifying_key();
        Ok(MlDsaKeypair {
            public: MlDsaPublicKey(vk),
            secret: MlDsaSecretKey(sk),
        })
    }

    pub fn public_key(&self) -> MlDsaPublicKey {
        MlDsaPublicKey(self.secret.0.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> Result<MlDsaSignature, CryptoError> {
        let sig = self.secret.0.sign(msg);
        Ok(MlDsaSignature(sig))
    }
}

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
