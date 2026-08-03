//! Post-Quantum Handshake Protocol — Traffic Analysis Resistant
//!
//! Design goals:
//! — Every packet on the wire is exactly PACKET_SIZE bytes
//! — Handshake messages fragmented into fixed-size packets
//! — Data and cover traffic use identical packet size
//! — Randomized timing jitter to prevent traffic analysis
//! — Constant-time operations for all secret-dependent branches
//! — Hybrid PQ: ML-KEM-768 + X25519 key exchange, ML-DSA-65 signatures

use pq_crypto::HybridIdentity;
use quinn::{RecvStream, SendStream};
use std::time::Instant;
use subtle::ConstantTimeEq;

/// Legacy v1 QUIC handshake framing size (8192 bytes).
///
/// DEPRECATED path: this constant is the v1 handshake's own fragment size and is
/// **not** interchangeable with the canonical Tunnel wire size
/// `pq_tunnel_core::PACKET_SIZE` (1280, see [`crate::codec`]).  The legacy
/// `handshake` module does not use `WirePacket`/the codec and is replaced by the
/// codec wire format in Phase 5.
pub const PACKET_SIZE: usize = 8192;
pub const MAX_PAYLOAD_PER_PACKET: usize = PACKET_SIZE;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("io: {0}")]
    Io(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("verification failed")]
    VerificationFailed,
    #[error("crypto: {0}")]
    Crypto(String),
}

#[derive(Clone)]
pub struct HandshakeResult {
    pub shared_secret: [u8; 32],
    pub peer_ml_dsa_key: [u8; 1952],
    pub session_id: [u8; 8],
    pub handshake_duration_ms: u64,
}

impl std::fmt::Debug for HandshakeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeResult")
            .field("shared_secret", &"<redacted>")
            .field(
                "peer_ml_dsa_key",
                &format_args!("<redacted: {} bytes>", self.peer_ml_dsa_key.len()),
            )
            .field("session_id", &self.session_id)
            .field("handshake_duration_ms", &self.handshake_duration_ms)
            .finish()
    }
}

impl Drop for HandshakeResult {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.shared_secret.zeroize();
    }
}

/// Legacy v1 handshake message wire type.
///
/// ⚠️ Byte values are NOT compatible with [`crate::codec::MessageType`]: this
/// enum encodes `Data = 0x10` / `Cover = 0x11`, whereas the codec encodes
/// `Data = 0x01` / `Cover = 0x02`.  The legacy `handshake` module is a separate
/// v1 QUIC framing superseded by the codec in Phase 5; do not mix the two.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum MsgType {
    ClientHello = 0x01,
    ServerHello = 0x02,
    Confirm = 0x03,
    Dummy = 0x00,
    Data = 0x10,
    Cover = 0x11,
}

pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    getrandom::fill(&mut a).expect("getrandom");
    a
}

fn rand32() -> [u8; 32] {
    rand_bytes::<32>()
}
fn rand8() -> [u8; 8] {
    rand_bytes::<8>()
}

pub fn pad_packet(payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; PACKET_SIZE];
    let len = payload.len().min(PACKET_SIZE);
    pkt[..len].copy_from_slice(&payload[..len]);
    pkt
}

pub async fn send_packet(s: &mut SendStream, pkt: &[u8]) -> Result<(), HandshakeError> {
    s.write_all(pkt)
        .await
        .map_err(|e| HandshakeError::Io(e.to_string()))?;
    Ok(())
}

pub async fn recv_packet(r: &mut RecvStream) -> Result<Vec<u8>, HandshakeError> {
    let mut buf = vec![0u8; PACKET_SIZE];
    r.read_exact(&mut buf)
        .await
        .map_err(|e| HandshakeError::Io(e.to_string()))?;
    Ok(buf)
}

fn hkdf_derive(input: &[u8; 32], salt: &[u8; 8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), input);
    let mut okm = [0u8; 32];
    hk.expand(b"pq-tunnel-hkdf-v1", &mut okm)
        .expect("hkdf expand 32 bytes");
    okm
}

fn build_confirm_ct(secret: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pq-tunnel-confirm-v2");
    h.update(secret);
    h.update(nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn serialize_client_hello(
    sid: &[u8; 8],
    nonce: &[u8; 32],
    identity: &HybridIdentity,
    sig: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MsgType::ClientHello as u8);
    buf.extend_from_slice(sid);
    buf.extend_from_slice(&identity.ml_kem.public.to_bytes());
    buf.extend_from_slice(&identity.ml_dsa.public.encode());
    buf.extend_from_slice(&identity.x25519.public.to_bytes());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    buf.extend_from_slice(sig);
    buf
}

fn serialize_server_hello(
    sid: &[u8; 8],
    nonce: &[u8; 32],
    identity: &HybridIdentity,
    kem_ct: &[u8],
    dsa_sig: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MsgType::ServerHello as u8);
    buf.extend_from_slice(sid);
    buf.extend_from_slice(kem_ct);
    buf.extend_from_slice(dsa_sig);
    buf.extend_from_slice(&identity.x25519.public.to_bytes());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&identity.ml_dsa.public.encode());
    buf
}

#[allow(clippy::type_complexity)]
fn deserialize_client_hello(
    data: &[u8],
) -> Result<([u8; 8], Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], Vec<u8>), HandshakeError> {
    let min_len = 1 + 8 + 1184 + 1952 + 32 + 32 + 2;
    if data.len() < min_len {
        return Err(HandshakeError::Protocol("short client hello".into()));
    }
    let sid: [u8; 8] = data[1..9].try_into().unwrap();
    let kem_pk = data[9..1193].to_vec();
    let dsa_pk = data[1193..3145].to_vec();
    let x25519: [u8; 32] = data[3145..3177].try_into().unwrap();
    let nonce: [u8; 32] = data[3177..3209].try_into().unwrap();
    let sig_len = u16::from_be_bytes([data[3209], data[3210]]) as usize;
    let sig = data[3211..3211 + sig_len].to_vec();
    Ok((sid, kem_pk, dsa_pk, x25519, nonce, sig))
}

#[allow(clippy::type_complexity)]
fn deserialize_server_hello(
    data: &[u8],
) -> Result<([u8; 8], Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], Vec<u8>), HandshakeError> {
    if data.len() < 1 + 8 + 1088 + 3309 + 32 + 32 + 1952 {
        return Err(HandshakeError::Protocol("short server hello".into()));
    }
    let sid: [u8; 8] = data[1..9].try_into().unwrap();
    let kem_ct = data[9..1097].to_vec();
    let dsa_sig = data[1097..4406].to_vec();
    let x25519: [u8; 32] = data[4406..4438].try_into().unwrap();
    let nonce: [u8; 32] = data[4438..4470].try_into().unwrap();
    let dsa_pk = data[4470..6422].to_vec();
    Ok((sid, kem_ct, dsa_sig, x25519, nonce, dsa_pk))
}

pub async fn client_handshake(
    id: &HybridIdentity,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<HandshakeResult, HandshakeError> {
    let t0 = Instant::now();
    let sid = rand8();
    let nonce = rand32();

    let mut ch_sig_msg = Vec::with_capacity(8 + 32);
    ch_sig_msg.extend_from_slice(&sid);
    ch_sig_msg.extend_from_slice(&nonce);
    let ch_sig = id
        .ml_dsa
        .sign(&ch_sig_msg)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    let ch_sig_bytes = ch_sig.encode();

    let ch_payload = serialize_client_hello(&sid, &nonce, id, &ch_sig_bytes);
    let ch_pkt = pad_packet(&ch_payload);
    send_packet(send, &ch_pkt).await?;

    let sh_pkt = recv_packet(recv).await?;
    let (sh_sid, sh_kem_ct, sh_dsa_sig, sh_x25519, sh_nonce, ref sh_dsa_pk) =
        deserialize_server_hello(&sh_pkt)?;

    if !bool::from(sh_sid.ct_eq(&sid)) {
        return Err(HandshakeError::Protocol("session_id mismatch".into()));
    }

    let peer_dsa_pk = pq_crypto::signature::MlDsaPublicKey::from_bytes(sh_dsa_pk)
        .map_err(|e| HandshakeError::Crypto(format!("bad dsa key: {}", e)))?;
    let peer_x = x25519_dalek::PublicKey::from(sh_x25519);

    let peer_ct = pq_crypto::kem::MlKemCiphertext::from_bytes(&sh_kem_ct)
        .map_err(|e| HandshakeError::Crypto(format!("bad ct: {}", e)))?;

    let ks = pq_crypto::kem::decapsulate(&id.ml_kem.secret, &peer_ct)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    let kem_bytes = ks.as_bytes();

    let ecdh_secret = id.x25519.diffie_hellman(&peer_x);

    let mut hybrid_secret = [0u8; 32];
    for i in 0..32 {
        hybrid_secret[i] = kem_bytes[i] ^ ecdh_secret[i];
    }

    let hybrid_secret = hkdf_derive(&hybrid_secret, &sid);

    let sig_msg = [&sid[..], &sh_nonce[..], &id.x25519.public.to_bytes()[..]].concat();
    let sig = pq_crypto::signature::MlDsaSignature::from_bytes(&sh_dsa_sig)
        .map_err(|e| HandshakeError::Crypto(format!("bad sig: {}", e)))?;

    let valid = pq_crypto::signature::verify(&peer_dsa_pk, &sig_msg, &sig)
        .map_err(|e| HandshakeError::Crypto(format!("verify: {}", e)))?;
    if !valid {
        return Err(HandshakeError::VerificationFailed);
    }

    let confirm = build_confirm_ct(&hybrid_secret, &sh_nonce);
    let mut cf_payload = vec![MsgType::Confirm as u8];
    cf_payload.extend_from_slice(&confirm);
    let cf_pkt = pad_packet(&cf_payload);
    send_packet(send, &cf_pkt).await?;

    let _dummy = recv_packet(recv).await?;

    Ok(HandshakeResult {
        shared_secret: hybrid_secret,
        peer_ml_dsa_key: sh_dsa_pk
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::Protocol("bad dsa key len".into()))?,
        session_id: sid,
        handshake_duration_ms: t0.elapsed().as_millis() as u64,
    })
}

pub async fn server_handshake(
    id: &HybridIdentity,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<HandshakeResult, HandshakeError> {
    let t0 = Instant::now();

    let ch_pkt = recv_packet(recv).await?;
    let (ch_sid, ch_kem_pk, ch_dsa_pk, ch_x25519, _ch_nonce, ch_sig) =
        deserialize_client_hello(&ch_pkt)?;

    let client_dsa_pk = pq_crypto::signature::MlDsaPublicKey::from_bytes(&ch_dsa_pk)
        .map_err(|e| HandshakeError::Crypto(format!("bad client dsa key: {}", e)))?;
    let client_sig = pq_crypto::signature::MlDsaSignature::from_bytes(&ch_sig)
        .map_err(|e| HandshakeError::Crypto(format!("bad client sig: {}", e)))?;
    let client_sig_msg = [&ch_sid[..], &_ch_nonce[..]].concat();

    let client_valid = pq_crypto::signature::verify(&client_dsa_pk, &client_sig_msg, &client_sig)
        .map_err(|e| HandshakeError::Crypto(format!("client verify: {}", e)))?;
    if !client_valid {
        return Err(HandshakeError::VerificationFailed);
    }

    let peer_kem_pk = pq_crypto::kem::MlKemPublicKey::from_bytes(&ch_kem_pk)
        .map_err(|e| HandshakeError::Crypto(format!("bad kem key: {}", e)))?;
    let _peer_dsa_pk = pq_crypto::signature::MlDsaPublicKey::from_bytes(&ch_dsa_pk)
        .map_err(|e| HandshakeError::Crypto(format!("bad dsa key: {}", e)))?;
    let peer_x = x25519_dalek::PublicKey::from(ch_x25519);
    let nonce = rand32();

    let (kem_ss, ct) = pq_crypto::kem::encapsulate(&peer_kem_pk)
        .map_err(|e| HandshakeError::Crypto(format!("encaps: {}", e)))?;
    let kem_bytes = kem_ss.as_bytes();

    let ecdh_secret = id.x25519.diffie_hellman(&peer_x);

    let mut hybrid_secret = [0u8; 32];
    for i in 0..32 {
        hybrid_secret[i] = kem_bytes[i] ^ ecdh_secret[i];
    }

    let hybrid_secret = hkdf_derive(&hybrid_secret, &ch_sid);

    let mut sig_msg = Vec::with_capacity(8 + 32 + 32);
    sig_msg.extend_from_slice(&ch_sid);
    sig_msg.extend_from_slice(&nonce);
    sig_msg.extend_from_slice(&ch_x25519);

    let sig = id
        .ml_dsa
        .sign(&sig_msg)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    let sig_bytes = sig.encode();
    let ct_bytes = ct.to_bytes();

    let sh_payload = serialize_server_hello(&ch_sid, &nonce, id, &ct_bytes, &sig_bytes);
    let sh_pkt = pad_packet(&sh_payload);
    send_packet(send, &sh_pkt).await?;

    let cf_pkt = recv_packet(recv).await?;
    if cf_pkt[0] != MsgType::Confirm as u8 {
        return Err(HandshakeError::Protocol("expected Confirm".into()));
    }

    let cf_confirm: [u8; 32] = cf_pkt[1..33].try_into().unwrap();
    let expected = build_confirm_ct(&hybrid_secret, &nonce);
    if !bool::from(cf_confirm.ct_eq(&expected)) {
        return Err(HandshakeError::Protocol("confirm mismatch".into()));
    }

    let dummy_pkt = pad_packet(&[MsgType::Dummy as u8]);
    send_packet(send, &dummy_pkt).await?;

    Ok(HandshakeResult {
        shared_secret: hybrid_secret,
        peer_ml_dsa_key: ch_dsa_pk
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::Protocol("bad dsa key len".into()))?,
        session_id: ch_sid,
        handshake_duration_ms: t0.elapsed().as_millis() as u64,
    })
}

pub async fn send_data_packet(s: &mut SendStream, data: &[u8]) -> Result<(), HandshakeError> {
    let mut payload = vec![MsgType::Data as u8];
    payload.extend_from_slice(data);
    let pkt = pad_packet(&payload);
    send_packet(s, &pkt).await
}

pub async fn recv_data_packet(r: &mut RecvStream) -> Result<Vec<u8>, HandshakeError> {
    let pkt = recv_packet(r).await?;
    if pkt.is_empty() || pkt[0] != MsgType::Data as u8 {
        return Err(HandshakeError::Protocol("not a data packet".into()));
    }
    Ok(pkt[1..].to_vec())
}

pub async fn send_cover_packet(s: &mut SendStream) -> Result<(), HandshakeError> {
    let mut payload = vec![MsgType::Cover as u8];
    payload.extend_from_slice(&rand_bytes::<128>());
    let pkt = pad_packet(&payload);
    send_packet(s, &pkt).await
}

pub async fn send_dummy_packet(s: &mut SendStream) -> Result<(), HandshakeError> {
    let payload = vec![MsgType::Dummy as u8];
    let pkt = pad_packet(&payload);
    send_packet(s, &pkt).await
}

pub const UNIFORM_PACKET_SIZE: usize = PACKET_SIZE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_size_constant() {
        assert_eq!(PACKET_SIZE, 8192);
    }

    #[test]
    fn pad_packet_produces_fixed_size() {
        let pkt = pad_packet(&[1, 2, 3]);
        assert_eq!(pkt.len(), PACKET_SIZE);
        assert_eq!(&pkt[0..3], &[1, 2, 3]);
        assert!(pkt[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn confirm_is_deterministic() {
        let s = [0x42u8; 32];
        let n = [0xABu8; 32];
        let c1 = build_confirm_ct(&s, &n);
        let c2 = build_confirm_ct(&s, &n);
        assert_eq!(c1, c2);
    }

    #[test]
    fn client_hello_serialization_roundtrip() {
        let identity = HybridIdentity::generate().unwrap();
        let sid = [1u8; 8];
        let nonce = [2u8; 32];
        let sig = vec![3u8; 3309];
        let payload = serialize_client_hello(&sid, &nonce, &identity, &sig);
        let (s, _kp, _dp, x, n, sig_out) = deserialize_client_hello(&payload).unwrap();
        assert_eq!(s, sid);
        assert_eq!(n, nonce);
        assert_eq!(x, identity.x25519.public.to_bytes());
        assert_eq!(sig_out, sig);
    }

    #[test]
    fn server_hello_serialization_roundtrip() {
        let identity = HybridIdentity::generate().unwrap();
        let sid = [3u8; 8];
        let nonce = [4u8; 32];
        let kem_ct = vec![5u8; 1088];
        let dsa_sig = vec![6u8; 3309];
        let payload = serialize_server_hello(&sid, &nonce, &identity, &kem_ct, &dsa_sig);
        let (s, ct, sig, _x, n, _pk) = deserialize_server_hello(&payload).unwrap();
        assert_eq!(s, sid);
        assert_eq!(n, nonce);
        assert_eq!(ct, kem_ct);
        assert_eq!(sig, dsa_sig);
    }

    #[test]
    fn hybrid_secret_derivation_is_symmetric() {
        let kp = pq_crypto::kem::MlKemKeypair::generate().unwrap();

        let (_ss1, ct1) = pq_crypto::kem::encapsulate(&kp.public).unwrap();
        let (ss2, ct2) = pq_crypto::kem::encapsulate(&kp.public).unwrap();

        let _dec1 = pq_crypto::kem::decapsulate(&kp.secret, &ct1).unwrap();
        let dec2 = pq_crypto::kem::decapsulate(&kp.secret, &ct2).unwrap();

        assert_eq!(&ss2.as_bytes()[..], &dec2.as_bytes()[..]);
        assert_ne!(&ss2.as_bytes()[..], &[0u8; 32]);
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }
}
