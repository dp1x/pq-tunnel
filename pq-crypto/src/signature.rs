use crate::error::CryptoError;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa65 as MlDsaParams, Seed,
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use zeroize::ZeroizeOnDrop;

pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

#[derive(Clone)]
pub struct MlDsaPublicKey(pub(crate) VerifyingKey<MlDsaParams>);

#[derive(Clone, ZeroizeOnDrop)]
pub struct MlDsaSecretKey(pub(crate) SigningKey<MlDsaParams>);

impl MlDsaSecretKey {
    /// Export this seed (32 bytes) — the canonical serialization of the
    /// ML-DSA-65 secret key.
    ///
    /// The seed unambiguously reconstructs the signing key (derivation is
    /// deterministic). Note this is *not* the FIPS-204 expanded encoding
    /// (4032 bytes); the `ml-dsa` crate stores the compact seed.
    ///
    /// The returned buffer is key material.
    pub fn to_seed(&self) -> [u8; 32] {
        let seed: Seed = self.0.to_seed();
        seed.into()
    }

    /// Reconstruct a signing key from its 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let seed: Seed = (*seed).into();
        MlDsaSecretKey(SigningKey::from_seed(&seed))
    }
}

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

    pub fn to_seed(&self) -> [u8; 32] {
        self.secret.to_seed()
    }

    /// Reconstruct a keypair from a 32-byte seed. The public key is derived
    /// deterministically, so a stored seed is sufficient to restore the pair.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = MlDsaSecretKey::from_seed(seed);
        let public = MlDsaPublicKey(secret.0.verifying_key());
        MlDsaKeypair { public, secret }
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
    fn ml_dsa_seed_roundtrip() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let seed = kp.to_seed();
        assert_eq!(seed.len(), 32, "ML-DSA-65 seed must be 32 bytes");

        let rebuilt = MlDsaKeypair::from_seed(&seed);

        assert_eq!(
            rebuilt.public_key().encode(),
            kp.public_key().encode(),
            "public key must be derivable from seed alone"
        );

        let msg = b"seed roundtrip message";
        let sig = rebuilt.sign(msg).expect("sign");
        let valid = verify(&kp.public, msg, &sig).expect("verify");
        assert!(valid, "rebuilt keypair must verify");
    }

    #[test]
    fn ml_dsa_seed_deterministic() {
        let seed = [7u8; 32];
        let a = MlDsaKeypair::from_seed(&seed);
        let b = MlDsaKeypair::from_seed(&seed);
        assert_eq!(
            a.public_key().encode(),
            b.public_key().encode(),
            "same seed must produce identical keypair"
        );
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

    // -----------------------------------------------------------------------
    // Known-answer tests (M5.1) — FIPS 204 via Wycheproof `testvectors_v1`
    // -----------------------------------------------------------------------

    #[test]
    fn ml_dsa_65_wycheproof_verify_kat() {
        use crate::kat_vectors::{DSA_MSG, DSA_PK, DSA_SIG, unhex};
        let pk = MlDsaPublicKey::from_bytes(&unhex(DSA_PK)).expect("pk decode");
        let sig = MlDsaSignature::from_bytes(&unhex(DSA_SIG)).expect("sig decode");
        let msg = unhex(DSA_MSG);
        let valid = verify(&pk, &msg, &sig).expect("verify");
        assert!(
            valid,
            "Wycheproof ML-DSA-65 tcId 1 (valid) signature must verify"
        );
    }

    #[test]
    fn ml_dsa_65_wycheproof_keygen_kat() {
        use crate::kat_vectors::{DSA_KEYGEN_PK, DSA_SEED, unhex};
        let seed: [u8; 32] = <[u8; 32]>::try_from(unhex(DSA_SEED).as_slice()).unwrap();
        let kp = MlDsaKeypair::from_seed(&seed);
        assert_eq!(
            kp.public.encode(),
            unhex(DSA_KEYGEN_PK),
            "FIPS 204 keyGen must reproduce the Wycheproof public key from the seed"
        );
    }

    /// Signing known-answer test, anchored to Wycheproof
    /// `mldsa_65_sign_seed_test.json` group 0 tcId 1.
    ///
    /// That vector omits both `rnd` and `ctx`, which its schema defines as the
    /// deterministic (all-zero `rnd`) empty-context case — exactly what the
    /// `ml-dsa` `Signer` implementation produces. This therefore pins the
    /// production `MlDsaKeypair::sign` path (not a raw crate type) to an
    /// externally supplied signature, and it fails if the dependency ever
    /// stops signing deterministically.
    #[test]
    fn ml_dsa_65_wycheproof_sign_kat() {
        use crate::kat_vectors::{DSA_MSG, DSA_SEED, DSA_SIG, unhex};
        let seed: [u8; 32] = <[u8; 32]>::try_from(unhex(DSA_SEED).as_slice()).unwrap();
        let kp = MlDsaKeypair::from_seed(&seed);
        let sig = kp.sign(&unhex(DSA_MSG)).expect("sign");
        assert_eq!(
            sig.encode(),
            unhex(DSA_SIG),
            "FIPS 204 deterministic signing must reproduce the Wycheproof signature"
        );
    }

    /// Pins the signing profile D13 records: ML-DSA-65 signing is deliberately
    /// deterministic (FIPS 204 Algorithm 2, `rnd = 0`). This exists so a
    /// dependency bump that silently switched to hedged signing would fail
    /// loudly instead of changing handshake bytes unnoticed.
    ///
    /// Determinism is safe here because every signed transcript binds a fresh
    /// per-session sid, ML-KEM encapsulation key and X25519 key, so no two
    /// sessions ever sign identical content (see DESIGN_DECISIONS D13).
    #[test]
    fn ml_dsa_sign_is_deterministic() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let msg = b"tunnel profile probe";
        let a = kp.sign(msg).expect("sign a");
        let b = kp.sign(msg).expect("sign b");
        assert_eq!(
            a.encode(),
            b.encode(),
            "ML-DSA-65 signing must stay deterministic (D13)"
        );
    }

    /// Distinct messages must yield distinct signatures even under
    /// determinism — determinism is per (key, message), not a constant.
    #[test]
    fn ml_dsa_distinct_messages_yield_distinct_signatures() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let a = kp.sign(b"message one").expect("sign a");
        let b = kp.sign(b"message two").expect("sign b");
        assert_ne!(
            a.encode(),
            b.encode(),
            "different transcripts must not produce the same signature"
        );
    }

    /// Negative verification: a single flipped byte must be rejected. Both
    /// rejection paths count — `from_bytes` may refuse it structurally
    /// (`Signature::decode` is not total over arbitrary 3309-byte input), or
    /// `verify` may return `Ok(false)`. Either way the tampered signature must
    /// never be accepted. This is the path an attacker reaches on the wire.
    #[test]
    fn ml_dsa_verify_rejects_tampered_signature() {
        use crate::kat_vectors::{DSA_MSG, DSA_PK, DSA_SIG, unhex};
        let pk = MlDsaPublicKey::from_bytes(&unhex(DSA_PK)).expect("pk decode");
        let msg = unhex(DSA_MSG);
        let original = unhex(DSA_SIG);

        // Byte offsets into the *decoded* signature, not the hex string.
        let mut structural = 0usize;
        let mut cryptographic = 0usize;
        for idx in [
            0usize,
            ML_DSA_65_SIGNATURE_BYTES / 2,
            ML_DSA_65_SIGNATURE_BYTES - 1,
        ] {
            let mut raw = original.clone();
            raw[idx] ^= 0x01;
            match MlDsaSignature::from_bytes(&raw) {
                Err(_) => structural += 1,
                Ok(sig) => {
                    let ok = verify(&pk, &msg, &sig).expect("verify");
                    assert!(
                        !ok,
                        "ML-DSA-65 verify must reject a signature with byte {idx} flipped"
                    );
                    cryptographic += 1;
                }
            }
        }
        assert!(
            structural + cryptographic == 3,
            "every tampered byte must be rejected by exactly one path"
        );
    }

    /// Wrong-length inputs must be rejected by the production parsers, which
    /// sit directly on the attacker-controlled handshake decode path
    /// (`handshake_v2.rs` ClientHello/ServerHello/ClientConfirm).
    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        use crate::kat_vectors::{DSA_PK, DSA_SIG, unhex};

        let pk = unhex(DSA_PK);
        assert!(
            MlDsaPublicKey::from_bytes(&pk[..ML_DSA_65_PUBLIC_KEY_BYTES - 1]).is_err(),
            "short ML-DSA public key must be rejected"
        );
        assert!(
            MlDsaPublicKey::from_bytes(&[0u8; ML_DSA_65_PUBLIC_KEY_BYTES + 1]).is_err(),
            "over-long ML-DSA public key must be rejected"
        );
        assert!(
            MlDsaPublicKey::from_bytes(&[]).is_err(),
            "empty ML-DSA public key must be rejected"
        );

        let sig = unhex(DSA_SIG);
        assert!(
            MlDsaSignature::from_bytes(&sig[..ML_DSA_65_SIGNATURE_BYTES - 1]).is_err(),
            "short ML-DSA signature must be rejected"
        );
        assert!(
            MlDsaSignature::from_bytes(&[0u8; ML_DSA_65_SIGNATURE_BYTES + 1]).is_err(),
            "over-long ML-DSA signature must be rejected"
        );
        assert!(
            MlDsaSignature::from_bytes(&[]).is_err(),
            "empty ML-DSA signature must be rejected"
        );
    }
}
