use crate::classical::{X25519Keypair, X25519PublicKey};
use crate::error::CryptoError;
use crate::kem::{MlKemCiphertext, MlKemKeypair, decapsulate};
use crate::signature::MlDsaKeypair;

#[derive(Debug)]
pub struct HybridIdentity {
    pub x25519: X25519Keypair,
    pub ml_kem: MlKemKeypair,
    pub ml_dsa: MlDsaKeypair,
}

impl HybridIdentity {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(HybridIdentity {
            x25519: X25519Keypair::generate(),
            ml_kem: MlKemKeypair::generate()?,
            ml_dsa: MlDsaKeypair::generate()?,
        })
    }

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

impl Clone for HybridIdentity {
    fn clone(&self) -> Self {
        HybridIdentity {
            x25519: X25519Keypair::generate(),
            ml_kem: MlKemKeypair::generate().expect("keygen"),
            ml_dsa: MlDsaKeypair::generate().expect("keygen"),
        }
    }
}