use crate::error::CryptoError;
use hybrid_array::Array;
use kem::{Ciphertext, Decapsulate, Encapsulate, SharedKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use rand_core::RngCore;
use typenum::consts::U32;
use zeroize::ZeroizeOnDrop;

/// ML-KEM-768 public key size in bytes.
pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;
/// ML-KEM-768 secret key size in bytes.
pub const ML_KEM_768_SECRET_KEY_BYTES: usize = 2400;
/// ML-KEM-768 ciphertext size in bytes.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
/// ML-KEM-768 shared secret size in bytes.
pub const ML_KEM_768_SHARED_SECRET_BYTES: usize = 32;

/// ML-KEM-768 public key (encapsulation key).
#[derive(Debug, Clone)]
pub struct MlKemPublicKey(pub(crate) EncapsulationKey);

/// ML-KEM-768 secret key (decapsulation key). Automatically zeroed on drop.
#[derive(Debug, ZeroizeOnDrop)]
pub struct MlKemSecretKey(pub(crate) DecapsulationKey);

/// ML-KEM-768 ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKemCiphertext(pub(crate) Ciphertext<MlKem768>);

/// ML-KEM-768 shared secret. Automatically zeroed on drop.
#[derive(Debug, ZeroizeOnDrop)]
pub struct MlKemSharedSecret(pub(crate) SharedKey<MlKem768>);

/// ML-KEM-768 keypair.
pub struct MlKemKeypair {
    pub public: MlKemPublicKey,
    pub secret: MlKemSecretKey,
}

impl MlKemKeypair {
    /// Generate a new ML-KEM-768 keypair using the system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let (dk, ek) = MlKem768::generate_keypair();
        Ok(MlKemKeypair {
            public: MlKemPublicKey(ek),
            secret: MlKemSecretKey(dk),
        })
    }
}

/// Encapsulate a shared secret under the given public key using the system CSPRNG.
pub fn encapsulate(
    pk: &MlKemPublicKey,
) -> Result<(MlKemSharedSecret, MlKemCiphertext), CryptoError> {
    let (ct, ss) = pk.0.encapsulate();
    Ok((
        MlKemSharedSecret(ss),
        MlKemCiphertext(ct),
    ))
}

/// Decapsulate a shared secret using the secret key and ciphertext.
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
