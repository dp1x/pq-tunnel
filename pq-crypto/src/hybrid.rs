use crate::classical::{X25519Keypair, X25519PublicKey};
use crate::error::CryptoError;
use crate::kem::{MlKemCiphertext, MlKemKeypair, decapsulate};
use crate::signature::MlDsaKeypair;

/// A hybrid identity containing classical (X25519) and post-quantum (ML-KEM, ML-DSA) keypairs.
pub struct HybridIdentity {
    pub x25519: X25519Keypair,
    pub ml_kem: MlKemKeypair,
    pub ml_dsa: MlDsaKeypair,
}

impl HybridIdentity {
    /// Generate a new hybrid identity with fresh keypairs.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(HybridIdentity {
            x25519: X25519Keypair::generate(),
            ml_kem: MlKemKeypair::generate()?,
            ml_dsa: MlDsaKeypair::generate()?,
        })
    }

    /// Derive the hybrid shared secret.
    pub fn derive_shared_secret(
        &self,
        peer_kem_ciphertext: &MlKemCiphertext,
        peer_x25519: &X25519PublicKey,
    ) -> Result<[u8; 32], CryptoError> {
        let kem_secret = decapsulate(&self.ml_kem.secret, peer_kem_ciphertext)?;
        let ecdh_secret = self.x25519.diffie_hellman(peer_x25519);

        let mut hybrid = [0u8; 32];
        for i in 0..32 {
            hybrid[i] = kem_secret.0[i] ^ ecdh_secret[i];
        }
        Ok(hybrid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::encapsulate;

    #[test]
    fn hybrid_identity_generation_succeeds() {
        let _identity = HybridIdentity::generate().expect("hybrid keygen");
    }

    #[test]
    fn hybrid_shared_secret_is_consistent_both_sides() {
        let id_a = HybridIdentity::generate().expect("keygen");
        let id_b = HybridIdentity::generate().expect("keygen");

        let (kem_secret_from_enc, ct) =
            encapsulate(&id_a.ml_kem.public).expect("encaps");

        let kem_secret_a = decapsulate(&id_a.ml_kem.secret, &ct).expect("decaps");
        assert_eq!(
            kem_secret_from_enc.0.as_slice(),
            kem_secret_a.0.as_slice(),
        );

        let hybrid_a = id_a
            .derive_shared_secret(&ct, &id_b.x25519.public)
            .expect("derive A");

        let ecdh_from_b = id_b.x25519.diffie_hellman(&id_a.x25519.public);
        let mut hybrid_b = [0u8; 32];
        for i in 0..32 {
            hybrid_b[i] = kem_secret_from_enc.0[i] ^ ecdh_from_b[i];
        }

        assert_eq!(
            hybrid_a, hybrid_b,
            "both sides must derive the same hybrid secret"
        );
    }
}
