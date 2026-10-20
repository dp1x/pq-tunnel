use crate::error::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub const KDF_SALT_BYTES: usize = 32;

pub fn kdf_derive(
    input: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::Kdf(format!("expand failed: {}", e)))?;
    Ok(okm)
}

/// HKDF-Expand into a fixed-size byte array, zeroizing the intermediate heap
/// buffer before returning so derived key material never lingers on the heap
/// (IMPLEMENTATION_GUIDE §6). All `derive_*` callers use this to avoid the
/// non-zeroizing `kdf_derive` → `Vec<u8>` escape path.
fn kdf_derive_to_bytes<const N: usize>(
    input: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; N], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input);
    let mut okm = vec![0u8; N];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::Kdf(format!("expand failed: {}", e)))?;
    let bytes: [u8; N] = okm
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Kdf("output size mismatch — unreachable".into()))?;
    okm.zeroize();
    Ok(bytes)
}

#[derive(Zeroize)]
pub struct MasterSecret(pub(crate) [u8; 32]);

impl MasterSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterSecret(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterSecret([REDACTED])")
    }
}

impl Clone for MasterSecret {
    fn clone(&self) -> Self {
        MasterSecret(self.0)
    }
}

impl Drop for MasterSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn derive_master_secret(
    kem_ss_c: &[u8; 32],
    kem_ss_s: &[u8; 32],
) -> Result<MasterSecret, CryptoError> {
    let ikm = [kem_ss_c.as_slice(), kem_ss_s.as_slice()].concat();
    let salt = [0u8; 32];
    let bytes = kdf_derive_to_bytes::<32>(&ikm, &salt, b"pq-tunnel-master-v1")?;
    Ok(MasterSecret(bytes))
}

/// Build the HKDF `info` field for a session-bound derivation: the purpose
/// label plus the session identifier.  Binding the `session_id` into the
/// derivation makes the derived keying material *per-session*, not merely
/// per-master: two sessions that share a master secret (PROTOCOL_SPEC §10
/// requires each session to use *unique* session protection keys) still derive
/// independent keys and nonce prefixes, so counter resets in one session can
/// never collide with another session's AEAD nonce space.
fn session_info(label: &[u8], session_id: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + session_id.len());
    info.extend_from_slice(label);
    info.extend_from_slice(session_id);
    info
}

pub fn derive_client_to_server_key(
    master: &MasterSecret,
    session_id: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let salt = [0u8; 32];
    let mut info = session_info(b"pq-tunnel-c2s-v2", session_id);
    let out = kdf_derive_to_bytes::<32>(master.as_bytes(), &salt, &info);
    info.zeroize();
    out
}

pub fn derive_server_to_client_key(
    master: &MasterSecret,
    session_id: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let salt = [0u8; 32];
    let mut info = session_info(b"pq-tunnel-s2c-v2", session_id);
    let out = kdf_derive_to_bytes::<32>(master.as_bytes(), &salt, &info);
    info.zeroize();
    out
}

pub fn derive_nonce_prefix_c2s(
    master: &MasterSecret,
    session_id: &[u8],
) -> Result<[u8; 4], CryptoError> {
    let salt = [0u8; 32];
    let mut info = session_info(b"pq-tunnel-nonce-c2s-v2", session_id);
    let out = kdf_derive_to_bytes::<4>(master.as_bytes(), &salt, &info);
    info.zeroize();
    out
}

pub fn derive_nonce_prefix_s2c(
    master: &MasterSecret,
    session_id: &[u8],
) -> Result<[u8; 4], CryptoError> {
    let salt = [0u8; 32];
    let mut info = session_info(b"pq-tunnel-nonce-s2c-v2", session_id);
    let out = kdf_derive_to_bytes::<4>(master.as_bytes(), &salt, &info);
    info.zeroize();
    out
}

pub fn derive_handshake_init_key(kem_ss: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let salt = [0u8; 32];
    kdf_derive_to_bytes::<32>(kem_ss, &salt, b"pq-tunnel-init-v1")
}

pub fn derive_handshake_init_nonce(kem_ss: &[u8; 32]) -> Result<[u8; 12], CryptoError> {
    let salt = [0u8; 32];
    kdf_derive_to_bytes::<12>(kem_ss, &salt, b"pq-tunnel-init-nonce-v1")
}

/// v2 handshake master derivation (DESIGN_DECISIONS D13, D14).
///
/// `master = HKDF-SHA256(ikm = ssA ‖ ssB ‖ dh_cs, salt = [0;32],
/// info = "pq-tunnel-master-v2" ‖ VERSION ‖ SID ‖ TH3)`.
///
/// - Concatenation order is pinned (`ssA ‖ ssB ‖ dh_cs` on both sides); XOR
///   combination is banned (the pre-v2 XOR-combiner derivation bug).
/// - The transcript digest `TH3` and the session identifier are bound into the
///   derivation, so a replayed handshake transcript or a shared-master session
///   never re-derives the same keying material.
/// - Unlike the v1 `derive_master_secret` (which leaves its `ikm` staging
///   buffer un-zeroized — see that function), the `ikm` and `info` staging
///   buffers here are zeroized after use (IMPLEMENTATION_GUIDE §6, D14).
pub fn derive_master_secret_v2(
    ss_a: &[u8; 32],
    ss_b: &[u8; 32],
    dh_cs: &[u8; 32],
    version: u8,
    session_id: &[u8],
    th3: &[u8],
) -> Result<MasterSecret, CryptoError> {
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(ss_a);
    ikm.extend_from_slice(ss_b);
    ikm.extend_from_slice(dh_cs);

    let mut info = Vec::with_capacity(b"pq-tunnel-master-v2".len() + 1 + session_id.len() + 32);
    info.extend_from_slice(b"pq-tunnel-master-v2");
    info.push(version);
    info.extend_from_slice(session_id);
    info.extend_from_slice(th3);

    let salt = [0u8; 32];
    let out = kdf_derive_to_bytes::<32>(&ikm, &salt, &info);
    ikm.zeroize();
    info.zeroize();
    out.map(MasterSecret)
}

/// Finished key for the v1 handshake's explicit client→server key
/// confirmation (DESIGN_DECISIONS D15).
///
/// `finished_key = HKDF(master, salt = [0;32],
/// info = "pq-tunnel-finished-v1" ‖ VERSION ‖ SID)`, 32 bytes.  The salt is
/// pinned to the zero 32-byte string (it is NOT the KEM shared secret — the
/// master is already the extract output).
pub fn derive_finished_key(
    master: &MasterSecret,
    version: u8,
    session_id: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut info = Vec::with_capacity(b"pq-tunnel-finished-v1".len() + 1 + session_id.len());
    info.extend_from_slice(b"pq-tunnel-finished-v1");
    info.push(version);
    info.extend_from_slice(session_id);

    let salt = [0u8; 32];
    let out = kdf_derive_to_bytes::<32>(master.as_bytes(), &salt, &info);
    info.zeroize();
    out
}

/// The client→server Finished MAC (DESIGN_DECISIONS D15).
///
/// `client_finished = HMAC-SHA256(finished_key, TH3)[..16]` — 16 bytes on the
/// wire.  Only the real client (holder of the ephemeral secret keys) can
/// compute it; the server verifies it before entering ESTABLISHED.
pub fn compute_client_finished(finished_key: &[u8; 32], th3: &[u8; 32]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(finished_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(th3);
    let digest = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&digest[..16]);
    tag
}

pub fn build_session_nonce(prefix: &[u8; 4], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(prefix);
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_derive_is_deterministic() {
        let out1 = kdf_derive(b"input", &[0u8; 32], b"label-v1", 32).unwrap();
        let out2 = kdf_derive(b"input", &[0u8; 32], b"label-v1", 32).unwrap();
        assert_eq!(out1, out2, "HKDF must be deterministic for same inputs");
    }

    #[test]
    fn kdf_two_labels_produce_different_output() {
        let ikm = [0xAAu8; 32];
        let salt = [0u8; 32];
        let out_a = kdf_derive(&ikm, &salt, b"label-a", 32).unwrap();
        let out_b = kdf_derive(&ikm, &salt, b"label-b", 32).unwrap();
        assert_ne!(out_a, out_b, "Different labels must produce different keys");
    }

    #[test]
    fn kdf_different_inputs_produce_different_output() {
        let salt = [0u8; 32];
        let out_a = kdf_derive(&[0x01u8; 32], &salt, b"label", 32).unwrap();
        let out_b = kdf_derive(&[0x02u8; 32], &salt, b"label", 32).unwrap();
        assert_ne!(out_a, out_b, "Different inputs must produce different keys");
    }

    #[test]
    fn kdf_output_length_matches_request() {
        let out = kdf_derive(b"input", &[0u8; 32], b"label", 64).unwrap();
        assert_eq!(out.len(), 64);
        let out_short = kdf_derive(b"input", &[0u8; 32], b"label", 4).unwrap();
        assert_eq!(out_short.len(), 4);
    }

    #[test]
    fn derive_master_secret_is_consistent() {
        let ss_c = [0x11u8; 32];
        let ss_s = [0x22u8; 32];
        let m = derive_master_secret(&ss_c, &ss_s).unwrap();
        let m2 = derive_master_secret(&ss_c, &ss_s).unwrap();
        assert_eq!(m.as_bytes(), m2.as_bytes());
    }

    /// Non-secret test session identifier (8 bytes, matching the codec's
    /// `SESSION_ID_LEN`).
    const TEST_SID: [u8; 8] = *b"test-sid";

    #[test]
    fn per_direction_keys_are_different() {
        let ss_c = [0x11u8; 32];
        let ss_s = [0x22u8; 32];
        let master = derive_master_secret(&ss_c, &ss_s).unwrap();
        let k_c2s = derive_client_to_server_key(&master, &TEST_SID).unwrap();
        let k_s2c = derive_server_to_client_key(&master, &TEST_SID).unwrap();
        assert_ne!(k_c2s, k_s2c, "C2S and S2C keys must differ");
    }

    #[test]
    fn nonce_prefixes_are_different() {
        let ss_c = [0x11u8; 32];
        let ss_s = [0x22u8; 32];
        let master = derive_master_secret(&ss_c, &ss_s).unwrap();
        let np_c2s = derive_nonce_prefix_c2s(&master, &TEST_SID).unwrap();
        let np_s2c = derive_nonce_prefix_s2c(&master, &TEST_SID).unwrap();
        assert_ne!(np_c2s, np_s2c, "Direction nonce prefixes must differ");
    }

    /// PROTOCOL_SPEC §10: sessions must use *unique* session protection keys.
    /// Two sessions sharing a master secret but using different session
    /// identifiers MUST derive different keys — otherwise a counter reset in
    /// one session could collide with the other's AEAD nonce space.
    #[test]
    fn different_session_ids_derive_different_keys() {
        let master = derive_master_secret(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        let sid_a = [0xAA; 8];
        let sid_b = [0xBB; 8];
        assert_ne!(
            derive_client_to_server_key(&master, &sid_a).unwrap(),
            derive_client_to_server_key(&master, &sid_b).unwrap(),
            "keys must differ across session identifiers"
        );
        assert_ne!(
            derive_server_to_client_key(&master, &sid_a).unwrap(),
            derive_server_to_client_key(&master, &sid_b).unwrap(),
            "keys must differ across session identifiers"
        );
    }

    /// CRYPTO_PROFILE §8: nonce uniqueness is mandatory.  Nonce prefixes must
    /// differ across sessions so two sessions sharing a master never overlap
    /// in AEAD nonce space.
    #[test]
    fn different_session_ids_derive_different_nonce_prefixes() {
        let master = derive_master_secret(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        let sid_a = [0xAA; 8];
        let sid_b = [0xBB; 8];
        assert_ne!(
            derive_nonce_prefix_c2s(&master, &sid_a).unwrap(),
            derive_nonce_prefix_c2s(&master, &sid_b).unwrap(),
            "nonce prefixes must differ across session identifiers"
        );
        assert_ne!(
            derive_nonce_prefix_s2c(&master, &sid_a).unwrap(),
            derive_nonce_prefix_s2c(&master, &sid_b).unwrap(),
            "nonce prefixes must differ across session identifiers"
        );
    }

    #[test]
    fn build_session_nonce_is_correct() {
        let prefix = [0xDE, 0xAD, 0xBE, 0xEF];
        let nonce = build_session_nonce(&prefix, 42);
        assert_eq!(&nonce[..4], &prefix);
        assert_eq!(nonce[4..], 42u64.to_be_bytes());
    }

    #[test]
    fn different_labels_all_distinct() {
        let ss_c = [0x11u8; 32];
        let ss_s = [0x22u8; 32];
        let master = derive_master_secret(&ss_c, &ss_s).unwrap();
        let k_c2s = derive_client_to_server_key(&master, &TEST_SID).unwrap();
        let k_s2c = derive_server_to_client_key(&master, &TEST_SID).unwrap();
        assert_ne!(k_c2s, k_s2c);
    }

    #[test]
    fn init_key_and_nonce_are_distinct() {
        let ss = [0x55u8; 32];
        let k = derive_handshake_init_key(&ss).unwrap();
        let n = derive_handshake_init_nonce(&ss).unwrap();
        assert_ne!(&k[..n.len()], &n[..], "init key and nonce must differ");
    }

    #[test]
    fn derive_master_secret_different_inputs() {
        let m1 = derive_master_secret(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        let m2 = derive_master_secret(&[0x33u8; 32], &[0x44u8; 32]).unwrap();
        assert_ne!(
            m1.as_bytes(),
            m2.as_bytes(),
            "different KEM shared secrets must produce different master secrets"
        );
    }

    // -----------------------------------------------------------------------
    // v2 handshake key schedule (DESIGN_DECISIONS D13/D14/D15)
    // -----------------------------------------------------------------------

    type V2Inputs = ([u8; 32], [u8; 32], [u8; 32], u8, [u8; 8], [u8; 32]);

    fn v2_inputs() -> V2Inputs {
        (
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            1u8,
            *b"test-sid",
            [0x44u8; 32],
        )
    }

    #[test]
    fn derive_master_secret_v2_is_deterministic() {
        let (a, b, dh, v, sid, th3) = v2_inputs();
        let m1 = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).unwrap();
        let m2 = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).unwrap();
        assert_eq!(m1.as_bytes(), m2.as_bytes());
    }

    #[test]
    fn derive_master_secret_v2_order_is_pinned() {
        // D13: concatenation order ssA ‖ ssB ‖ dh_cs is pinned on both sides.
        // Swapping the two KEM shares MUST change the master, or the server and
        // client could disagree (and an attacker could re-frame shares).
        let (a, b, dh, v, sid, th3) = v2_inputs();
        let m_ab = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).unwrap();
        let m_ba = derive_master_secret_v2(&b, &a, &dh, v, &sid, &th3).unwrap();
        assert_ne!(
            m_ab.as_bytes(),
            m_ba.as_bytes(),
            "ssA/ssB order must be pinned (no symmetric combiner)"
        );
    }

    #[test]
    fn derive_master_secret_v2_binds_dh_leg() {
        let (a, b, dh, v, sid, th3) = v2_inputs();
        let mut dh2 = dh;
        dh2[0] ^= 0x01;
        let m1 = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).unwrap();
        let m2 = derive_master_secret_v2(&a, &b, &dh2, v, &sid, &th3).unwrap();
        assert_ne!(m1.as_bytes(), m2.as_bytes(), "X25519 leg must be bound in");
    }

    #[test]
    fn derive_master_secret_v2_binds_version_sid_th3() {
        let (a, b, dh, v, sid, th3) = v2_inputs();
        let base = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).unwrap();

        let v2 = derive_master_secret_v2(&a, &b, &dh, v + 1, &sid, &th3).unwrap();
        assert_ne!(base.as_bytes(), v2.as_bytes(), "version must be bound in");

        let mut sid2 = sid;
        sid2[0] ^= 0x01;
        let s2 = derive_master_secret_v2(&a, &b, &dh, v, &sid2, &th3).unwrap();
        assert_ne!(base.as_bytes(), s2.as_bytes(), "sid must be bound in");

        let mut th3_2 = th3;
        th3_2[0] ^= 0x01;
        let t2 = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3_2).unwrap();
        assert_ne!(base.as_bytes(), t2.as_bytes(), "TH3 must be bound in");
    }

    #[test]
    fn derive_master_secret_v2_label_is_disjoint_from_v1() {
        // Label separation: the v2 master derivation must never collide with
        // the v1 path for the same underlying inputs.
        let (a, b, _dh, _v, _sid, _th3) = v2_inputs();
        let v1 = derive_master_secret(&a, &b).unwrap();
        let v2 =
            derive_master_secret_v2(&a, &b, &[0x33u8; 32], 1, b"test-sid", &[0x44; 32]).unwrap();
        assert_ne!(v1.as_bytes(), v2.as_bytes());
    }

    #[test]
    fn derive_finished_key_is_deterministic_and_bound() {
        let (a, b, dh, v, sid, th3) = v2_inputs();
        let master = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).unwrap();
        let fk1 = derive_finished_key(&master, v, &sid).unwrap();
        let fk2 = derive_finished_key(&master, v, &sid).unwrap();
        assert_eq!(fk1, fk2);

        let fk_v = derive_finished_key(&master, v + 1, &sid).unwrap();
        assert_ne!(fk1, fk_v, "version must be bound into finished key");

        let mut sid2 = sid;
        sid2[0] ^= 0x01;
        let fk_s = derive_finished_key(&master, v, &sid2).unwrap();
        assert_ne!(fk1, fk_s, "sid must be bound into finished key");
    }

    #[test]
    fn finished_key_is_label_separated_from_traffic_keys() {
        // D14 one-way, domain-separated hierarchy: the Finished key must not
        // collide with the traffic keys derived from the same master.
        let (a, b, dh, v, sid, th3) = v2_inputs();
        let master = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).unwrap();
        let fk = derive_finished_key(&master, v, &sid).unwrap();
        let k_c2s = derive_client_to_server_key(&master, &sid).unwrap();
        let k_s2c = derive_server_to_client_key(&master, &sid).unwrap();
        assert_ne!(fk, k_c2s);
        assert_ne!(fk, k_s2c);
        assert_ne!(fk, master.as_bytes().as_slice());
    }

    /// Independent hand-rolled HMAC-SHA256 (RFC 2104) used only in tests to
    /// cross-check `compute_client_finished` without depending on the hmac
    /// crate's own implementation.
    fn hmac_sha256_manual(key: &[u8], msg: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let block = 64usize;
        let mut k = [0u8; 64];
        if key.len() > block {
            let h = Sha256::digest(key);
            k[..32].copy_from_slice(&h);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..block {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(msg);
        let inner_h = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_h);
        let out = outer.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        bytes
    }

    #[test]
    fn compute_client_finished_matches_rfc2104_hmac_sha256() {
        // Cross-check against an independent HMAC implementation: the 16-byte
        // truncation must equal the first 16 bytes of full HMAC-SHA256.
        let key = [0x5au8; 32];
        let th3 = [0x7bu8; 32];
        let got = compute_client_finished(&key, &th3);
        let expected = hmac_sha256_manual(&key, &th3);
        assert_eq!(&got[..], &expected[..16]);
        assert_eq!(got.len(), 16);
    }

    #[test]
    fn compute_client_finished_is_deterministic_and_sensitive() {
        let key = [0x11u8; 32];
        let th3 = [0x22u8; 32];
        let f1 = compute_client_finished(&key, &th3);
        let f2 = compute_client_finished(&key, &th3);
        assert_eq!(f1, f2);

        let mut th3_2 = th3;
        th3_2[0] ^= 0x01;
        assert_ne!(f1, compute_client_finished(&key, &th3_2));

        let mut key2 = key;
        key2[0] ^= 0x01;
        assert_ne!(f1, compute_client_finished(&key2, &th3));
    }

    // -----------------------------------------------------------------------
    // Known-answer test (M5.1) — RFC 5869 §A.1 test case 1 (D21)
    // -----------------------------------------------------------------------

    #[test]
    fn rfc5869_a1_hkdf_sha256_kat() {
        use crate::kat_vectors::{RFC5869_IKM, RFC5869_INFO, RFC5869_OKM, RFC5869_SALT, unhex};
        // KAT1: IKM of 22 octets of 0x0b, salt 0x000102..0c, info 0xf0f1..f9, L=42.
        let okm = kdf_derive(
            &unhex(RFC5869_IKM),
            &unhex(RFC5869_SALT),
            &unhex(RFC5869_INFO),
            42,
        )
        .expect("HKDF expand must succeed within the 255×HashLen bound");
        assert_eq!(
            okm,
            unhex(RFC5869_OKM),
            "RFC 5869 §A.1 OKM (42 octets) must match exactly"
        );
    }

    // -----------------------------------------------------------------------
    // Domain-separation matrix (Item 3)
    // -----------------------------------------------------------------------

    /// A `derive_*` entry point that yields 32 bytes from a fixed master.
    type LabelDerive = fn(&MasterSecret, &[u8]) -> Result<[u8; 32], CryptoError>;

    /// Every `info` label the key schedule can put in front of HKDF, paired
    /// with a `derive` that produces 32 bytes from a fixed master.
    ///
    /// Self-derived (not an external anchor): the assertion is that distinct
    /// labels never collide for the same key material, i.e. that the label is
    /// actually load-bearing in the `info` string. A label that were dropped
    /// from the `info` construction would make two rows of this table equal
    /// and fail the pairwise test below.
    const SEPARATION_LABELS: [(&str, LabelDerive); 5] = [
        ("pq-tunnel-c2s-v2", |m, sid| {
            derive_client_to_server_key(m, sid)
        }),
        ("pq-tunnel-s2c-v2", |m, sid| {
            derive_server_to_client_key(m, sid)
        }),
        ("pq-tunnel-nonce-c2s-v2", |m, sid| {
            let p = derive_nonce_prefix_c2s(m, sid)?;
            let mut out = [0u8; 32];
            out[..4].copy_from_slice(&p);
            Ok(out)
        }),
        ("pq-tunnel-nonce-s2c-v2", |m, sid| {
            let p = derive_nonce_prefix_s2c(m, sid)?;
            let mut out = [0u8; 32];
            out[..4].copy_from_slice(&p);
            Ok(out)
        }),
        ("pq-tunnel-finished-v1", |m, sid| {
            derive_finished_key(m, PROTOCOL_VERSION_FOR_KDF_TESTS, sid)
        }),
    ];

    /// Protocol version byte used by the separation matrix. Pinned to `2`
    /// (the codec's `PROTOCOL_VERSION`) so the matrix does not silently track
    /// a future version bump without review.
    const PROTOCOL_VERSION_FOR_KDF_TESTS: u8 = 2;

    /// Every pair of distinct labels must yield distinct keying material from
    /// the same master. Cross-label separation is the whole point of the
    /// `-v1`/`-v2` suffixes (D14), and it is what stops the Finished key,
    /// the traffic keys, and the nonce prefixes from sharing a derivation.
    #[test]
    fn every_kdf_label_is_pairwise_separated() {
        let master = derive_master_secret(&[0x11u8; 32], &[0x22u8; 32]).expect("master");
        let mut seen: Vec<(&str, [u8; 32])> = Vec::new();
        for (label, derive) in SEPARATION_LABELS {
            let out = derive(&master, &TEST_SID).expect("derive");
            for (prior_label, prior) in &seen {
                assert_ne!(
                    &out, prior,
                    "labels {label:?} and {prior_label:?} must not collide"
                );
            }
            seen.push((label, out));
        }
        assert_eq!(seen.len(), SEPARATION_LABELS.len());
    }

    /// The v1 master derivation (`pq-tunnel-master-v1`) and the v2 master
    /// derivation (`pq-tunnel-master-v2`) must never coincide, even for
    /// identical KEM shares and sid. This is the version-separation half of
    /// D14: an attacker must not be able to present a v1-shaped derivation
    /// where a v2 one is expected.
    #[test]
    fn master_labels_v1_and_v2_are_separated() {
        let (a, b, dh, v, sid, th3) = v2_inputs();
        let v1 = derive_master_secret(&a, &b).expect("v1");
        let v2 = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).expect("v2");
        assert_ne!(
            v1.as_bytes(),
            v2.as_bytes(),
            "pq-tunnel-master-v1 and -v2 must not collide"
        );

        // Nor may the v1 master equal the finished key derived from the v2
        // master (different ikm, different label, different length class).
        let fk = derive_finished_key(&v2, v, &sid).expect("finished");
        assert_ne!(v1.as_bytes(), &fk);
    }

    /// The handshake-init labels (`pq-tunnel-init-v1`,
    /// `pq-tunnel-init-nonce-v1`) must be separated from each other *and* from
    /// every traffic/finished label. The init key and nonce share the same
    /// `ikm` (a bare KEM shared secret) and the same salt, so the label is
    /// the only thing keeping them apart.
    #[test]
    fn handshake_init_labels_are_separated_from_traffic_labels() {
        let ss = [0x5au8; 32];
        let key = derive_handshake_init_key(&ss).expect("init key");
        let nonce = derive_handshake_init_nonce(&ss).expect("init nonce");
        assert_ne!(
            &key[..AEAD_NONCE_TEST_BYTES],
            &nonce[..AEAD_NONCE_TEST_BYTES],
            "pq-tunnel-init-v1 and -init-nonce-v1 must not collide"
        );

        let master = MasterSecret::from_bytes(ss);
        let traffic: Vec<[u8; 32]> = SEPARATION_LABELS
            .iter()
            .map(|(_, d)| d(&master, &TEST_SID).expect("derive"))
            .collect();
        for out in &traffic {
            assert_ne!(
                &key[..],
                &out[..],
                "pq-tunnel-init-v1 must not collide with a traffic/finished key"
            );
            assert_ne!(
                &nonce[..AEAD_NONCE_TEST_BYTES],
                &out[..AEAD_NONCE_TEST_BYTES],
                "pq-tunnel-init-nonce-v1 must not collide with a traffic/finished key"
            );
        }
    }

    /// The nonce prefix is a 4-byte truncation of a 32-byte derivation. A
    /// truncation can in principle collide even when the full derivations do
    /// not, so the 4-byte prefixes are compared against each other directly.
    #[test]
    fn nonce_prefixes_are_pairwise_distinct_as_four_byte_values() {
        let master = derive_master_secret(&[0x11u8; 32], &[0x22u8; 32]).expect("master");
        let c2s = derive_nonce_prefix_c2s(&master, &TEST_SID).expect("c2s");
        let s2c = derive_nonce_prefix_s2c(&master, &TEST_SID).expect("s2c");
        assert_ne!(c2s, s2c, "4-byte nonce prefixes must differ");

        // The nonce prefix must never equal the first 4 bytes of either
        // traffic key either — otherwise a nonce prefix and a key share a
        // prefix by accident rather than by construction.
        let k_c2s = derive_client_to_server_key(&master, &TEST_SID).expect("k");
        let k_s2c = derive_server_to_client_key(&master, &TEST_SID).expect("k");
        assert_ne!(&c2s[..], &k_c2s[..4]);
        assert_ne!(&s2c[..], &k_s2c[..4]);
    }

    /// Length of the init nonce used in the comparison above. The nonce is 12
    /// bytes; the comparison window is the shorter 4-byte prefix so the same
    /// slice length applies to the 32-byte key output.
    const AEAD_NONCE_TEST_BYTES: usize = 4;

    // -----------------------------------------------------------------------
    // Hybrid key-schedule binding surface (Item 2)
    // -----------------------------------------------------------------------

    /// The v2 master derivation binds exactly these inputs:
    /// `ikm = ss_a ‖ ss_b ‖ dh_cs` and
    /// `info = "pq-tunnel-master-v2" ‖ version ‖ session_id ‖ th3`.
    ///
    /// Note what is **not** in that set: the ML-KEM ciphertexts `ct2`/`ct3`
    /// and the ephemeral X25519/ML-KEM *public keys*. Those are not direct
    /// HKDF inputs. They are nevertheless bound into the derivation
    /// transitively, because `TH3` (fed to `info`) covers `M1_z ‖ M2_z ‖
    /// M3_z`, and `ct2`/`ct3` and both public keys are fields of those
    /// messages (D13). This test pins the *direct* binding surface so the
    /// argument stays visible: if a future revision drops `th3` from `info`,
    /// the ciphertext/public keys stop being bound and this test still passes
    /// (it only inspects the direct inputs), so the transitive binding must be
    /// re-argued deliberately.
    ///
    /// Self-derived (not an external anchor).
    #[test]
    fn master_v2_direct_binding_surface_is_pinned() {
        let (a, b, dh, v, sid, th3) = v2_inputs();

        // Every direct input is load-bearing.
        let base = derive_master_secret_v2(&a, &b, &dh, v, &sid, &th3).expect("base");

        let mut b2 = b;
        b2[31] ^= 0x80;
        assert_ne!(
            derive_master_secret_v2(&a, &b2, &dh, v, &sid, &th3)
                .expect("mutated")
                .as_bytes(),
            base.as_bytes(),
            "ss_b (the server's KEM share) must be bound directly"
        );

        let mut a2 = a;
        a2[0] ^= 0x40;
        assert_ne!(
            derive_master_secret_v2(&a2, &b, &dh, v, &sid, &th3)
                .expect("mutated")
                .as_bytes(),
            base.as_bytes(),
            "ss_a (the client's KEM share) must be bound directly"
        );

        // The ikm is exactly 96 bytes in the order ss_a ‖ ss_b ‖ dh_cs: a
        // rotation that swaps two legs must change the master.
        let rotated = derive_master_secret_v2(&b, &a, &dh, v, &sid, &th3).expect("rotated");
        assert_ne!(rotated.as_bytes(), base.as_bytes());
    }

    /// An empty `th3` and an all-zero `th3` must produce different masters,
    /// proving `th3` is concatenated (not merely length-checked) into `info`.
    ///
    /// Self-derived (not an external anchor).
    #[test]
    fn master_v2_distinguishes_absent_and_zero_transcript() {
        let (a, b, dh, v, sid, _th3) = v2_inputs();
        let empty = derive_master_secret_v2(&a, &b, &dh, v, &sid, &[]).expect("empty th3");
        let zero = derive_master_secret_v2(&a, &b, &dh, v, &sid, &[0u8; 32]).expect("zero th3");
        let real = derive_master_secret_v2(&a, &b, &dh, v, &sid, &[0x44u8; 32]).expect("real th3");
        assert_ne!(empty.as_bytes(), zero.as_bytes());
        assert_ne!(zero.as_bytes(), real.as_bytes());
        assert_ne!(empty.as_bytes(), real.as_bytes());
    }

    /// `session_id` is concatenated into `info` after a single `version` byte.
    /// A one-byte sid appended to a two-byte version must therefore be
    /// ambiguous unless `version` is fixed-width — which it is (exactly one
    /// byte, `u8`). This test pins that a version bump and a sid change are
    /// independently observable, which is what rules out a
    /// (version ‖ sid) re-splitting collision between two peers.
    ///
    /// Self-derived (not an external anchor).
    #[test]
    fn master_v2_version_and_sid_are_independently_observable() {
        let (a, b, dh, _v, sid, th3) = v2_inputs();
        let base = derive_master_secret_v2(&a, &b, &dh, 1, &sid, &th3).expect("base");

        let mut sid_shift = sid;
        sid_shift.rotate_left(1);
        assert_ne!(
            derive_master_secret_v2(&a, &b, &dh, 1, &sid_shift, &th3)
                .expect("shifted sid")
                .as_bytes(),
            base.as_bytes()
        );
        assert_ne!(
            derive_master_secret_v2(&a, &b, &dh, 2, &sid, &th3)
                .expect("v2")
                .as_bytes(),
            base.as_bytes()
        );
    }
}
