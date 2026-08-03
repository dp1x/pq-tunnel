use crate::error::CryptoError;
use kem::{Ciphertext, Decapsulate, Encapsulate, Kem, KeyExport, SharedKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use zeroize::ZeroizeOnDrop;

pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;
pub const ML_KEM_768_SECRET_KEY_BYTES: usize = 2400;
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
pub const ML_KEM_768_SHARED_SECRET_BYTES: usize = 32;

#[derive(Clone)]
pub struct MlKemPublicKey(pub(crate) EncapsulationKey<MlKem768>);

#[derive(Clone, ZeroizeOnDrop)]
pub struct MlKemSecretKey(pub(crate) DecapsulationKey<MlKem768>);

#[derive(Clone, PartialEq, Eq)]
pub struct MlKemCiphertext(pub(crate) Ciphertext<MlKem768>);

impl std::fmt::Debug for MlKemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKemPublicKey([REDACTED])")
    }
}

impl std::fmt::Debug for MlKemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKemSecretKey([REDACTED])")
    }
}

impl std::fmt::Debug for MlKemCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKemCiphertext([REDACTED])")
    }
}

impl MlKemCiphertext {
    pub fn new(inner: Ciphertext<MlKem768>) -> Self {
        MlKemCiphertext(inner)
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct MlKemSharedSecret(pub(crate) SharedKey<MlKem768>);

impl std::fmt::Debug for MlKemSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKemSharedSecret([REDACTED])")
    }
}

impl MlKemSharedSecret {
    pub fn as_bytes(&self) -> [u8; 32] {
        use std::convert::TryFrom;
        let slice: &[u8] = &self.0;
        <[u8; 32]>::try_from(slice).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct MlKemKeypair {
    pub public: MlKemPublicKey,
    pub secret: MlKemSecretKey,
}

impl MlKemKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (dk, ek) = MlKem768::generate_keypair();
        Ok(MlKemKeypair {
            public: MlKemPublicKey(ek),
            secret: MlKemSecretKey(dk),
        })
    }
}

impl MlKemPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key_bytes = <[u8; 1184]>::try_from(bytes)
            .map_err(|_| CryptoError::Kem("invalid kem key length".into()))?;
        let key_array = hybrid_array::Array::<u8, _>::from(key_bytes);
        EncapsulationKey::<MlKem768>::new(&key_array)
            .map(MlKemPublicKey)
            .map_err(|e| CryptoError::Kem(format!("invalid kem key: {:?}", e)))
    }

    pub fn inner(&self) -> &EncapsulationKey<MlKem768> {
        &self.0
    }
}

impl MlKemCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_slice().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let ct_bytes = <[u8; ML_KEM_768_CIPHERTEXT_BYTES]>::try_from(bytes)
            .map_err(|_| CryptoError::Kem("invalid ciphertext length".into()))?;
        Ok(MlKemCiphertext(Ciphertext::<MlKem768>::from(ct_bytes)))
    }
}

pub fn encapsulate(
    pk: &MlKemPublicKey,
) -> Result<(MlKemSharedSecret, MlKemCiphertext), CryptoError> {
    let (ct, ss) = pk.0.encapsulate();
    Ok((MlKemSharedSecret(ss), MlKemCiphertext(ct)))
}

pub fn decapsulate(
    sk: &MlKemSecretKey,
    ct: &MlKemCiphertext,
) -> Result<MlKemSharedSecret, CryptoError> {
    let ss = sk.0.decapsulate(&ct.0);
    Ok(MlKemSharedSecret(ss))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_768_keypair_generation_succeeds() {
        let _kp = MlKemKeypair::generate().expect("keygen");
    }

    #[test]
    fn ml_kem_768_encaps_decaps_roundtrip() {
        let kp = MlKemKeypair::generate().expect("keygen");
        let (shared_secret, ciphertext) = encapsulate(&kp.public).expect("encaps");
        let recovered = decapsulate(&kp.secret, &ciphertext).expect("decaps");
        assert_eq!(
            shared_secret.0.as_slice(),
            recovered.0.as_slice(),
            "KEM roundtrip must recover same shared secret"
        );
    }

    #[test]
    fn ml_kem_768_ciphertext_has_correct_size() {
        let kp = MlKemKeypair::generate().expect("keygen");
        let (_, ct) = encapsulate(&kp.public).expect("encaps");
        assert_eq!(ct.0.len(), ML_KEM_768_CIPHERTEXT_BYTES);
    }

    #[test]
    fn ml_kem_768_shared_secret_has_correct_size() {
        let kp = MlKemKeypair::generate().expect("keygen");
        let (ss, _) = encapsulate(&kp.public).expect("encaps");
        assert_eq!(ss.0.len(), ML_KEM_768_SHARED_SECRET_BYTES);
    }
}
