//! Identity provisioning for the v2 (datagram) product path.
//!
//! Static identities and rosters are provisioned out of band as
//! human-inspectable text files with a minimal, versioned header. This is a
//! provisioning convenience, not a protocol:
//!
//! ```text
//! PQTI
//! version: 1
//! type: identity
//! <hex payload>
//! ```
//!
//! The `type` field is one of:
//!
//! * `identity`   — the 32-byte ML-DSA-65 seed (secret), hex, one line.
//! * `public-key` — the 1952-byte encoded ML-DSA-65 public key, hex, one line.
//! * `roster`     — one hex-encoded public key per line; blank lines and `#`
//!   comments are ignored. An empty roster is rejected (fails closed — D12).
//!
//! The header is strict: an unknown magic, version, or type is rejected (no
//! silent downgrade). `identity` and `public-key` payloads must be exactly one
//! line of the expected byte length.
//!
//! All returned or intermediate secret buffers are zeroized on drop or error
//! paths. These functions never log key material.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use pq_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, MlDsaKeypair, MlDsaPublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

/// Size of the ML-DSA-65 secret seed on disk (the `ml-dsa` crate's canonical
/// compact secret serialization — *not* the FIPS-204 expanded encoding).
const SEED_BYTES: usize = 32;

/// First line of every provisioning file (magic string).
const MAGIC: &str = "PQTI";

/// Current provisioning file format version.
const FORMAT_VERSION: u8 = 1;

/// Key material types carried by provisioning files.
///
/// The `as_str` tokens are stability-relevant: changing them breaks existing
/// files (this type is only used to select the expected format).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KeyType {
    Identity,
    PublicKey,
    Roster,
}

impl KeyType {
    fn as_str(self) -> &'static str {
        match self {
            KeyType::Identity => "identity",
            KeyType::PublicKey => "public-key",
            KeyType::Roster => "roster",
        }
    }
}

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
    #[error("{}: could not create (it already exists)", path.display())]
    Exists { path: PathBuf },
    #[error("{}: missing or invalid header ({reason})", path.display())]
    BadHeader { path: PathBuf, reason: String },
    #[error(
        "{}: header type {:?} (expected {:?})",
        path.display(),
        got,
        expected
    )]
    BadType {
        path: PathBuf,
        expected: &'static str,
        got: String,
    },
}

#[allow(clippy::manual_is_multiple_of)] // is_multiple_of is stable >= 1.87; workspace MSRV is 1.85
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
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

fn write_header(out: &mut String, key_type: KeyType) {
    out.push_str(MAGIC);
    out.push('\n');
    out.push_str("version: ");
    out.push_str(&FORMAT_VERSION.to_string());
    out.push('\n');
    out.push_str("type: ");
    out.push_str(key_type.as_str());
    out.push('\n');
}

/// Read a provisioning file and validate its header strictly.
///
/// Returns the trimmed payload lines (comments and blank lines removed).
/// A wrong magic, version, or type fails closed (no silent downgrade).
fn read_payload_lines(path: &Path, expected: KeyType) -> Result<Vec<String>, IdentityError> {
    let mut raw = fs::read_to_string(path).map_err(|source| IdentityError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    // The raw buffer holds the hex of the (possibly secret) payload; scrub it
    // before it reaches the allocator. All checks happen inside the closure so
    // the borrow of `raw` is gone before `zeroize`.
    let result: Result<Vec<String>, IdentityError> = (|| {
        let lines: Vec<&str> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        if lines.len() < 3 {
            return Err(IdentityError::BadHeader {
                path: path.to_path_buf(),
                reason: "expected PQTI/version/type header".into(),
            });
        }
        if lines[0] != MAGIC {
            return Err(IdentityError::BadHeader {
                path: path.to_path_buf(),
                reason: format!("magic line {:?} (expected {:?})", lines[0], MAGIC),
            });
        }
        if lines[1] != format!("version: {}", FORMAT_VERSION) {
            return Err(IdentityError::BadHeader {
                path: path.to_path_buf(),
                reason: format!("unsupported format version {:?}", lines[1]),
            });
        }
        let got = lines[2].to_string();
        if lines[2] != format!("type: {}", expected.as_str()) {
            return Err(IdentityError::BadType {
                path: path.to_path_buf(),
                expected: expected.as_str(),
                got,
            });
        }

        Ok(lines[3..].iter().map(|l| l.to_string()).collect())
    })();
    raw.zeroize();
    result
}

/// Decode payload lines into hex blobs with per-type structural validation.
///
/// `identity`/`public-key` must have exactly one payload line; `roster` must
/// have at least one (empty rosters fail closed). When `blob_len` is non-zero
/// every decoded blob must be exactly that many bytes.
fn parse_blobs(
    path: &Path,
    expected: KeyType,
    blob_len: usize,
) -> Result<Vec<Vec<u8>>, IdentityError> {
    let mut lines = read_payload_lines(path, expected)?;

    // The payload lines are hex text of (possibly secret) key material; scrub
    // them as they are decoded so no copy reaches the allocator alive.
    let mut blobs = Vec::with_capacity(lines.len());
    for line in &mut lines {
        let mut blob = match decode_hex(line) {
            Ok(b) => b,
            Err(reason) => {
                line.zeroize();
                lines.zeroize();
                return Err(IdentityError::BadHex {
                    path: path.to_path_buf(),
                    reason,
                });
            }
        };
        if blob_len != 0 && blob.len() != blob_len {
            let got = blob.len();
            blob.zeroize();
            line.zeroize();
            lines.zeroize();
            return Err(IdentityError::BadLength {
                path: path.to_path_buf(),
                expected: blob_len,
                got,
            });
        }
        line.zeroize();
        blobs.push(blob);
    }

    match expected {
        KeyType::Identity | KeyType::PublicKey => {
            if blobs.len() != 1 {
                let n = blobs.len();
                blobs.zeroize();
                return Err(IdentityError::BadHeader {
                    path: path.to_path_buf(),
                    reason: format!("expected exactly one payload line, got {n}"),
                });
            }
        }
        KeyType::Roster => {
            if blobs.is_empty() {
                return Err(IdentityError::EmptyRoster {
                    path: path.to_path_buf(),
                });
            }
        }
    }

    Ok(blobs)
}

/// Write `content` to `path` atomically: write to a same-directory temp file
/// and rename over the target. A crash mid-write never leaves a truncated
/// provisioning file, and the rename replaces an existing target (Windows and
/// Unix).
fn write_atomic(path: &Path, content: &str) -> Result<(), IdentityError> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pqti".to_string());
    let tmp = dir.join(format!(".{}.{}.tmp", file_name, std::process::id()));

    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.map_err(|source| IdentityError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Fail unless `path` can be created new: atomically reserves the name
/// (O_EXCL semantics) so an existing file is never silently replaced. This is
/// the kernel-enforced no-clobber guard for `keygen`; callers may pass
/// `--force` to skip it.
pub fn ensure_missing(path: &Path) -> Result<(), IdentityError> {
    use std::io::ErrorKind;

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => Err(IdentityError::Exists {
            path: path.to_path_buf(),
        }),
        Err(source) => Err(IdentityError::Write {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Load an identity (secret) from a `type: identity` file.
pub fn load_identity(path: &Path) -> Result<MlDsaKeypair, IdentityError> {
    let mut blobs = parse_blobs(path, KeyType::Identity, SEED_BYTES)?;
    let mut seed = blobs.remove(0);
    let mut fixed: [u8; SEED_BYTES] = [0; SEED_BYTES];
    fixed.copy_from_slice(&seed);
    seed.zeroize();

    let keypair = MlDsaKeypair::from_seed(&fixed);
    fixed.zeroize();
    Ok(keypair)
}

/// Write an identity (secret seed) as a `type: identity` file.
pub fn save_identity(path: &Path, keypair: &MlDsaKeypair) -> Result<(), IdentityError> {
    let mut seed = keypair.to_seed();
    let mut content = String::new();
    write_header(&mut content, KeyType::Identity);
    content.push_str(&encode_hex(&seed));
    content.push('\n');
    seed.zeroize();

    let res = write_atomic(path, &content);
    content.zeroize();
    res
}

/// Load a pinned peer public key from a `type: public-key` file.
pub fn load_public_key(path: &Path) -> Result<MlDsaPublicKey, IdentityError> {
    let mut blobs = parse_blobs(path, KeyType::PublicKey, ML_DSA_65_PUBLIC_KEY_BYTES)?;
    let blob = blobs.remove(0);
    MlDsaPublicKey::from_bytes(&blob).map_err(|e| IdentityError::BadPublicKey {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Write a public key as a `type: public-key` file.
pub fn save_public_key(path: &Path, key: &MlDsaPublicKey) -> Result<(), IdentityError> {
    let mut content = String::new();
    write_header(&mut content, KeyType::PublicKey);
    content.push_str(&encode_hex(&key.encode()));
    content.push('\n');

    write_atomic(path, &content)
}

/// Load a roster (list of trusted client public keys) from a `type: roster` file.
///
/// One encoded public key per payload line; blank lines and `#` comment lines
/// are ignored. An empty parsed result is an error (fails closed — D12).
pub fn load_roster(path: &Path) -> Result<Vec<MlDsaPublicKey>, IdentityError> {
    let blobs = parse_blobs(path, KeyType::Roster, ML_DSA_65_PUBLIC_KEY_BYTES)?;

    let mut roster = Vec::with_capacity(blobs.len());
    for blob in blobs {
        let key = MlDsaPublicKey::from_bytes(&blob).map_err(|e| IdentityError::BadPublicKey {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        roster.push(key);
    }
    Ok(roster)
}

/// Write a roster (list of trusted client public keys) as a `type: roster` file.
///
/// An empty roster is rejected (fails closed — D12).
pub fn save_roster(path: &Path, keys: &[MlDsaPublicKey]) -> Result<(), IdentityError> {
    if keys.is_empty() {
        return Err(IdentityError::EmptyRoster {
            path: path.to_path_buf(),
        });
    }

    let mut content = String::new();
    write_header(&mut content, KeyType::Roster);
    for key in keys {
        content.push_str(&encode_hex(&key.encode()));
        content.push('\n');
    }

    write_atomic(path, &content)
}

/// Append a public key to a roster file, creating it if missing.
///
/// Appending an already-present key is a no-op (idempotent). A missing file is
/// created with the roster header. Any existing file must parse as a valid
/// roster (fails closed).
pub fn append_roster(path: &Path, key: &MlDsaPublicKey) -> Result<(), IdentityError> {
    let mut keys = if path.exists() {
        load_roster(path)?
    } else {
        Vec::new()
    };

    if !keys.iter().any(|k| k.encode() == key.encode()) {
        // Rebuild the key from its encoding. `from_bytes` here cannot fail: the
        // encoding was just produced by a valid key; a failure still fails
        // closed rather than panicking.
        let copy =
            MlDsaPublicKey::from_bytes(&key.encode()).map_err(|e| IdentityError::BadPublicKey {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
        keys.push(copy);
    }

    save_roster(path, &keys)
}

/// Short, stable fingerprint of a public key for out-of-band verification.
///
/// `SHA-256(encoded_key)[..16]`, hex-encoded (32 chars): a 128-bit digest,
/// strong enough that a mismatch cannot be a collision. The full encoded key
/// never appears in logs or fingerprints.
pub fn fingerprint(key: &MlDsaPublicKey) -> String {
    let enc = key.encode();
    let digest = Sha256::digest(&enc);
    encode_hex(&digest[..16])
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

    fn header_file(kind: &str, payload: &[&str]) -> String {
        let mut s = format!("PQTI\nversion: 1\ntype: {kind}\n");
        for line in payload {
            s.push_str(line);
            s.push('\n');
        }
        s
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
    fn identity_file_has_pqti_header() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("identity-format");

        save_identity(&path, &kp).expect("save");
        let raw = fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = raw.lines().collect();

        assert_eq!(lines[0], "PQTI");
        assert_eq!(lines[1], "version: 1");
        assert_eq!(lines[2], "type: identity");
        assert_eq!(
            lines[3].len(),
            SEED_BYTES * 2,
            "seed payload must be 64 hex chars"
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
        fs::write(&path, header_file("identity", &["00"])).expect("write"); // 1 byte, not 32

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
        fs::write(
            &path,
            header_file("identity", &["zz".repeat(SEED_BYTES).as_str()]),
        )
        .expect("write");

        let err = load_identity(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadHex { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn load_rejects_wrong_magic() {
        let path = temp_path("identity-badmagic");
        let mut bad = String::from("XXXX\nversion: 1\ntype: identity\n");
        bad.push_str(&"ab".repeat(SEED_BYTES));
        fs::write(&path, bad).expect("write");

        let err = load_identity(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadHeader { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn load_rejects_unsupported_version() {
        let path = temp_path("identity-badversion");
        let mut bad = String::from("PQTI\nversion: 2\ntype: identity\n");
        bad.push_str(&"ab".repeat(SEED_BYTES));
        fs::write(&path, bad).expect("write");

        let err = load_identity(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadHeader { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn load_rejects_wrong_type() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("identity-wrongtype");
        save_public_key(&path, &kp.public_key()).expect("write");

        let err = load_identity(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadType { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn roster_roundtrip_with_comments() {
        let a = MlDsaKeypair::generate().expect("keygen");
        let b = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("roster-roundtrip");

        let content = header_file(
            "roster",
            &[
                "# tunnel roster",
                &encode_hex(&a.public_key().encode()),
                "",
                &encode_hex(&b.public_key().encode()),
            ],
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
        fs::write(&path, header_file("roster", &["# nothing here"])).expect("write");

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
        fs::write(&path, header_file("roster", &["not-hex"])).expect("write");

        let err = load_roster(&path).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadHex { .. }),
            "unexpected: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn roster_append_creates_file() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("roster-append-create");

        append_roster(&path, &kp.public_key()).expect("append");
        let roster = load_roster(&path).expect("load");
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0].encode(), kp.public_key().encode());
        cleanup(&path);
    }

    #[test]
    fn roster_append_is_idempotent() {
        let a = MlDsaKeypair::generate().expect("keygen");
        let b = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("roster-append-dup");

        append_roster(&path, &a.public_key()).expect("append");
        append_roster(&path, &b.public_key()).expect("append");
        append_roster(&path, &a.public_key()).expect("append dup");
        let roster = load_roster(&path).expect("load");
        assert_eq!(roster.len(), 2, "duplicate append must be a no-op");
        cleanup(&path);
    }

    #[test]
    fn roster_rejects_corrupt_existing_file_on_append() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let path = temp_path("roster-append-corrupt");
        fs::write(&path, "garbage").expect("write");

        let err = append_roster(&path, &kp.public_key()).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadHeader { .. }),
            "append to a corrupt roster must fail closed, got: {err}"
        );
        cleanup(&path);
    }

    #[test]
    fn fingerprint_is_stable_and_hex() {
        let kp = MlDsaKeypair::generate().expect("keygen");
        let fp = fingerprint(&kp.public_key());
        assert_eq!(fp.len(), 32, "fingerprint must be 32 hex chars");
        assert_eq!(
            fp,
            fingerprint(&kp.public_key()),
            "fingerprint must be stable"
        );
        assert!(fp.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
