use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

pub type X25519PublicKey = PublicKey;
pub type X25519SecretKey = StaticSecret;

#[derive(Clone)]
pub struct X25519Keypair {
    pub public: X25519PublicKey,
    pub secret: X25519SecretKey,
}

impl fmt::Debug for X25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519Keypair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl X25519Keypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        X25519Keypair { public, secret }
    }

    pub fn diffie_hellman(&self, other: &X25519PublicKey) -> [u8; 32] {
        let shared = self.secret.diffie_hellman(other);
        *shared.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keypair_generation_succeeds() {
        let kp = X25519Keypair::generate();
        let pub_bytes: [u8; 32] = kp.public.to_bytes();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn x25519_diffie_hellman_symmetric() {
        let kp_a = X25519Keypair::generate();
        let kp_b = X25519Keypair::generate();

        let secret_ab = kp_a.diffie_hellman(&kp_b.public);
        let secret_ba = kp_b.diffie_hellman(&kp_a.public);

        assert_eq!(secret_ab, secret_ba, "X25519 DH must be symmetric");
        assert_ne!(secret_ab, [0u8; 32], "shared secret must not be all zeros");
    }

    #[test]
    fn x25519_different_keypairs_produce_different_secrets() {
        let kp_a = X25519Keypair::generate();
        let kp_b = X25519Keypair::generate();
        let kp_c = X25519Keypair::generate();

        let secret_ab = kp_a.diffie_hellman(&kp_b.public);
        let secret_ac = kp_a.diffie_hellman(&kp_c.public);

        assert_ne!(
            secret_ab, secret_ac,
            "different keypairs must produce different shared secrets"
        );
    }
}
