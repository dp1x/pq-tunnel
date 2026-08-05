//! Identity provisioning for the v2 (datagram) product path.
//!
//! Static identities and rosters are provisioned out of band as hex files
//! (git-friendly, human-inspectable). Formats on disk:
//!
//! * Identity (secret) file: the 32-byte ML-DSA-65 seed, hex-encoded, one
//!   line, no trailing whitespace — e.g. `aabb...` (64 hex chars).
//! * Public key file: the 1952-byte encoded ML-DSA-65 public key, hex-encoded,
//!   one line (3904 hex chars).
//! * Roster file: one hex-encoded public key per line; blank lines and `#`
//!   comments are ignored. An empty roster is rejected (fails closed — D12).
//!
//! All returned or intermediate secret buffers are zeroized on drop or error
//! paths. These functions never log key material.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use pq_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, MlDsaKeypair, MlDsaPublicKey};
use thiserror::Error;
use zeroize::Zeroize;

/// Size of the ML-DSA-65 secret seed on disk (the `ml-dsa` crate's canonical
/// compact secret serialization — *not* the FIPS-204 expanded encoding).
const SEED_BYTES: usize = 32;

/// Hex-encoded length of a seed (2 chars per byte).
const SEED_HEX_LEN: usize = SEED_BYTES * 2;

/// Hex-encoded length of a public key.
const PUBLIC_KEY_HEX_LEN: usize = ML_DSA_65_PUBLIC_KEY_BYTES * 2;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{}: expected {expected} bytes, got {got}", path.display())]
    BadLength {
        path: PathBuf,
        expected: usize,
        got: usize,
    },
    #[error("{}: invalid hex: {reason}", path.display())]
    BadHex { path: PathBuf, reason: String },
    #[error("{}: invalid public key: {reason}", path.display())]
    BadPublicKey { path: PathBuf, reason: String },
    #[error("{}: empty roster (fails closed)", path.display())]
    EmptyRoster { path: PathBuf },
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex characters".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in 0..bytes.len() / 2 {
        let hi = match bytes[i * 2] {
            b'0'..=b'9' => bytes[i * 2] - b'0',
            b'a'..=b'f' => bytes[i * 2] - b'a' + 10,
            b'A'..=b'F' => bytes[i * 2] - b'A' + 10,
            c => return Err(format!("invalid hex character '{}'", c as char)),
        };
        let lo = match bytes[i * 2 + 1] {
            b'0'..=b'9' => bytes[i * 2 + 1] - b'0',
            b'a'..=b'f' => bytes[i * 2 + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[i * 2 + 1] - b'A' + 10,
            c => return Err(format!("invalid hex character '{}'", c as char)),
        };
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Read a file that must contain a single hex-encoded fixed-size blob.
fn read_hex_blob(path: &Path, expected_bytes: usize) -> Result<Vec<u8>, IdentityError> {
    let raw = fs::read_to_string(path).map_err(|source| IdentityError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let trimmed = raw.trim();
    if trimmed.len() != expected_bytes * 2 {
        return Err(IdentityError::BadLength {
            path: path.to_path_buf(),
            expected: expected_bytes,
            got: trimmed.len() / 2,
        });
    }
    decode_hex(trimmed).map_err(|reason| IdentityError::BadHex {
        path: path.to_path_buf(),
        reason,
    })
}

/// Load an identity (secret) from a hex-encoded 32-byte seed file.
pub fn load_identity(path: &Path) -> Result<MlDsaKeypair, IdentityError> {
    let mut seed = read_hex_blob(path, SEED_BYTES)?;
    let mut fixed: [u8; SEED_BYTES] = [0; SEED_BYTES];
    fixed.copy_from_slice(&seed);
    seed.zeroize();

    let keypair = MlDsaKeypair::from_seed(&fixed);
    fixed.zeroize();
    Ok(keypair)
}

/// Write an identity (secret seed) as a hex file.
pub fn save_identity(path: &Path, keypair: &MlDsaKeypair) -> Result<(), IdentityError> {
    let seed = keypair.to_seed();
    let hex = encode_hex(&seed);
    let mut seed = seed;
    seed.zeroize();

    fs::write(path, hex).map_err(|source| IdentityError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Load a pinned server public key from a hex-encoded encoded-key file.
pub fn load_public_key(path: &Path) -> Result<MlDsaPublicKey, IdentityError> {
    let blob = read_hex_blob(path, ML_DSA_65_PUBLIC_KEY_BYTES)?;
    MlDsaPublicKey::from_bytes(&blob).map_err(|e| IdentityError::BadPublicKey {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Write a public key as a hex file.
pub fn save_public_key(path: &Path, key: &MlDsaPublicKey) -> Result<(), IdentityError> {
    let hex = encode_hex(&key.encode());
    fs::write(path, hex).map_err(|source| IdentityError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Load a roster (list of trusted client public keys) from a hex file.
///
/// One encoded public key per line; blank lines and `#` comment lines are
/// ignored. An empty parsed result is an error (fails closed — D12).
pub fn load_roster(path: &Path) -> Result<Vec<MlDsaPublicKey>, IdentityError> {
    let raw = fs::read_to_string(path).map_err(|source| IdentityError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let mut roster: Vec<MlDsaPublicKey> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() != PUBLIC_KEY_HEX_LEN {
            return Err(IdentityError::BadLength {
                path: path.to_path_buf(),
                expected: ML_DSA_65_PUBLIC_KEY_BYTES,
                got: line.len() / 2,
            });
        }
        let blob = decode_hex(line).map_err(|reason| IdentityError::BadHex {
            path: path.to_path_buf(),
            reason,
        })?;
        let key = MlDsaPublicKey::from_bytes(&blob).map_err(|e| IdentityError::BadPublicKey {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        roster.push(key);
    }

    if roster.is_empty() {
        return Err(IdentityError::EmptyRoster {
            path: path.to_path_buf(),
        });
    }
    Ok(roster)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pq-tunnel-{}-{}", name, std::process::id()))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identity_hex_roundtrip() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("identity-roundtrip");

        save_identity(&path, &kp).expect("save");
        let loaded = load_identity(&path).expect("load");

        assert_eq!(
            loaded.public_key().encode(),
            kp.public_key().encode(),
            "loaded identity must match saved identity"
        );
        cleanup(&path);
    }

    #[test]
    fn identity_filename_is_64_hex_chars() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("identity-format");

        save_identity(&path, &kp).expect("save");
        let raw = fs::read_to_string(&path).expect("read");
        assert_eq!(
            raw.trim().len(),
            SEED_HEX_LEN,
            "seed file must be 64 hex chars"
        );
        cleanup(&path);
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("pk-roundtrip");

        save_public_key(&path, &kp.public_key()).expect("save");
        let loaded = load_public_key(&path).expect("load");

        assert_eq!(loaded.encode(), kp.public_key().encode());
        cleanup(&path);
    }

    #[test]
    fn load_identity_rejects_wrong_length() {
        let path = temp_path("identity-badlen");
        fs::write(&path, "00").expect("write"); // 1 byte, not 32

        let err = load_identity(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadLength { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn load_identity_rejects_bad_hex() {
        let path = temp_path("identity-badhex");
        fs::write(&path, "zz".repeat(SEED_BYTES)).expect("write");

        let err = load_identity(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadHex { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn roster_roundtrip_with_comments() {
        let a = MlDsaKeypair::generate().expect("keygen");
        let b = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("roster-roundtrip");

        let content = format!(
            "# tunnel roster\n {}\n\n{}\n",
            encode_hex(&a.public_key().encode()),
            encode_hex(&b.public_key().encode())
        );
        fs::write(&path, content).expect("write");

        let roster = load_roster(&path).expect("load");
        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].encode(), a.public_key().encode());
        assert_eq!(roster[1].encode(), b.public_key().encode());
        cleanup(&path);
    }

    #[test]
    fn empty_roster_fails_closed() {
        let path = temp_path("roster-empty");
        fs::write(&path, "# nothing here\n\n").expect("write");

        let err = load_roster(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::EmptyRoster { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn roster_rejects_bad_line() {
        let path = temp_path("roster-badline");
        fs::write(&path, "not-hex").expect("write");

        let err = load_roster(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadLength { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }
}
