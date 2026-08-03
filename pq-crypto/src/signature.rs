use crate::error::CryptoError;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa65 as MlDsaParams, Signature,
    Signer, SigningKey, Verifier, VerifyingKey,
};
use zeroize::ZeroizeOnDrop;

pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

#[derive(Clone)]
pub struct MlDsaPublicKey(pub(crate) VerifyingKey<MlDsaParams>);

#[derive(Clone, ZeroizeOnDrop)]
pub struct MlDsaSecretKey(pub(crate) SigningKey<MlDsaParams>);

#[derive(Clone, PartialEq)]
pub struct MlDsaSignature(pub(crate) ml_dsa::Signature<MlDsaParams>);

pub struct MlDsaKeypair {
    pub public: MlDsaPublicKey,
    pub secret: MlDsaSecretKey,
}

impl Clone for MlDsaKeypair {
    fn clone(&self) -> Self {
        MlDsaKeypair {
            public: self.public.clone(),
            secret: self.secret.clone(),
        }
    }
}

impl std::fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaPublicKey([REDACTED])")
    }
}

impl std::fmt::Debug for MlDsaSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaSecretKey([REDACTED])")
    }
}

impl std::fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaSignature([REDACTED])")
    }
}

impl std::fmt::Debug for MlDsaKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsaKeypair {{ public: MlDsaPublicKey([REDACTED]), secret: [REDACTED] }}"
        )
    }
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

impl MlDsaPublicKey {
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded = EncodedVerifyingKey::<MlDsaParams>::try_from(bytes)
            .map_err(|_| CryptoError::Signature("invalid dsa key length".into()))?;
        Ok(MlDsaPublicKey(VerifyingKey::decode(&encoded)))
    }

    pub fn inner(&self) -> &VerifyingKey<MlDsaParams> {
        &self.0
    }
}

impl MlDsaSignature {
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded = EncodedSignature::<MlDsaParams>::try_from(bytes)
            .map_err(|_| CryptoError::Signature("invalid signature length".into()))?;
        match Signature::decode(&encoded) {
            Some(sig) => Ok(MlDsaSignature(sig)),
            None => Err(CryptoError::Signature("signature decode failed".into())),
        }
    }

    pub fn inner(&self) -> &ml_dsa::Signature<MlDsaParams> {
        &self.0
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
    fn ml_dsa_65_sign_verify_roundtrip() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let msg = b"hello post-quantum world";
        let sig = kp.sign(msg).expect("sign");
        let valid = verify(&kp.public, msg, &sig).expect("verify");
        assert!(valid, "valid signature must verify");
    }

    #[test]
    fn ml_dsa_signature_encode_decode_roundtrip() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let msg = b"test message for encode/decode roundtrip";
        let sig = kp.sign(msg).expect("sign");

        let encoded = sig.encode();
        assert_eq!(
            encoded.len(),
            3309,
            "ML-DSA-65 signature must be 3309 bytes"
        );

        let decoded = MlDsaSignature::from_bytes(&encoded).expect("from_bytes");

        let valid = verify(&kp.public, msg, &decoded).expect("verify");
        assert!(
            valid,
            "decoded signature must verify against original message"
        );
    }

    #[test]
    fn ml_dsa_public_key_encode_decode_roundtrip() {
        let kp = MlDsaKeypair::generate().expect("keygen");

        let encoded = kp.public.encode();
        assert_eq!(
            encoded.len(),
            1952,
            "ML-DSA-65 public key must be 1952 bytes"
        );

        let decoded = MlDsaPublicKey::from_bytes(&encoded).expect("from_bytes");

        let msg = b"test message";
        let sig = kp.sign(msg).expect("sign");
        let valid = verify(&decoded, msg, &sig).expect("verify");
        assert!(valid, "decoded public key must verify original signature");
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
