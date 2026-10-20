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
use pq_tunnel_core::HandshakeV2ServerConfig;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

/// Size of the ML-DSA-65 secret seed on disk (the `ml-dsa` crate's canonical
/// compact secret serialization — *not* the FIPS-204 expanded encoding).
const SEED_BYTES: usize = 32;

/// Maximum number of client keys a roster file may hold.
///
/// The value is the core's default roster bound, so the parser and the
/// handshake machine can never disagree about what a legal roster is (the
/// server verifies the client signature against the **entire** roster, with
/// no early exit — D12 — so the roster size is a bound on the server's
/// per-handshake work, not a cosmetic limit).  The core's bound is
/// operator-overridable per deployment; the provisioning parser uses the
/// default, which is the right place for a file-format limit: a roster file
/// larger than this is not loadable by a default deployment.
pub const MAX_ROSTER_SIZE: usize = HandshakeV2ServerConfig::DEFAULT_MAX_ROSTER_SIZE;

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
    #[error(
        "{}: roster of {got} keys exceeds the maximum of {max} (fails closed)",
        path.display()
    )]
    RosterTooLarge {
        path: PathBuf,
        got: usize,
        max: usize,
    },
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
/// have at least one (empty rosters fail closed) and at most
/// [`MAX_ROSTER_SIZE`] (an over-long roster fails closed, and is rejected
/// *before* any key is materialised, so a hostile or corrupt file cannot
/// force an unbounded number of ML-DSA-65 key decodes).  When `blob_len` is
/// non-zero every decoded blob must be exactly that many bytes.
///
/// `max_payloads` is the maximum number of payload lines the file may
/// contain; `None` means "no early limit" (the identity/public-key types
/// enforce their own exact-count rule after decoding, so that their error
/// behaviour is unchanged).
fn parse_blobs(
    path: &Path,
    expected: KeyType,
    blob_len: usize,
    max_payloads: Option<usize>,
) -> Result<Vec<Vec<u8>>, IdentityError> {
    let mut lines = read_payload_lines(path, expected)?;

    // Count the payload lines BEFORE decoding any of them: the roster bound
    // must stop a hostile file from forcing an unbounded number of key
    // decodes, and a decoded key is far more expensive than a line count.
    //
    // MSRV 1.85: nested `if` (let chains stabilize in 1.88). Cannot be
    // collapsed into a `&& let` chain without breaking the MSRV gate.
    #[allow(clippy::collapsible_if)]
    if let Some(max) = max_payloads {
        if lines.len() > max {
            let got = lines.len();
            lines.zeroize();
            return Err(IdentityError::RosterTooLarge {
                path: path.to_path_buf(),
                got,
                max,
            });
        }
    }

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
    let mut blobs = parse_blobs(path, KeyType::Identity, SEED_BYTES, None)?;
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
    let mut blobs = parse_blobs(path, KeyType::PublicKey, ML_DSA_65_PUBLIC_KEY_BYTES, None)?;
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
/// are ignored. An empty parsed result is an error (fails closed — D12), and
/// so is a roster with more than [`MAX_ROSTER_SIZE`] keys (fails closed: the
/// server verifies the client signature against the *entire* roster with no
/// early exit — D12 — so an unbounded roster is an unbounded pre-authentication
/// work amplifier).  The size check runs before any key is decoded.
pub fn load_roster(path: &Path) -> Result<Vec<MlDsaPublicKey>, IdentityError> {
    load_roster_with_limit(path, MAX_ROSTER_SIZE)
}

/// Load a roster with an explicit size limit.
///
/// Same rules as [`load_roster`], with the limit supplied by the caller.  A
/// deployment that raises the server's roster bound
/// (`ServerConfig::max_roster_size`) must load its roster with the same
/// bound, or the provisioning file and the server would disagree about what
/// a legal roster is.
pub fn load_roster_with_limit(
    path: &Path,
    max_roster_size: usize,
) -> Result<Vec<MlDsaPublicKey>, IdentityError> {
    let blobs = parse_blobs(
        path,
        KeyType::Roster,
        ML_DSA_65_PUBLIC_KEY_BYTES,
        Some(max_roster_size),
    )?;

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
/// An empty roster is rejected (fails closed — D12), and so is a roster with
/// more than [`MAX_ROSTER_SIZE`] keys: a file the loader would refuse to
/// read is not a file the writer should produce.
pub fn save_roster(path: &Path, keys: &[MlDsaPublicKey]) -> Result<(), IdentityError> {
    if keys.is_empty() {
        return Err(IdentityError::EmptyRoster {
            path: path.to_path_buf(),
        });
    }
    if keys.len() > MAX_ROSTER_SIZE {
        return Err(IdentityError::RosterTooLarge {
            path: path.to_path_buf(),
            got: keys.len(),
            max: MAX_ROSTER_SIZE,
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
/// roster (fails closed).  A roster that is already at [`MAX_ROSTER_SIZE`]
/// keys is not grown: the append is refused and the file is left untouched.
pub fn append_roster(path: &Path, key: &MlDsaPublicKey) -> Result<(), IdentityError> {
    let mut keys = if path.exists() {
        load_roster(path)?
    } else {
        Vec::new()
    };

    if !keys.iter().any(|k| k.encode() == key.encode()) {
        if keys.len() >= MAX_ROSTER_SIZE {
            return Err(IdentityError::RosterTooLarge {
                path: path.to_path_buf(),
                got: keys.len() + 1,
                max: MAX_ROSTER_SIZE,
            });
        }
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

/// A hot-swappable client roster backed by a provisioning file (D27).
///
/// The invariant is **parse-then-swap, never mutate-in-place**: a reload
/// builds a complete new roster off to the side, validates it fully, and only
/// then replaces the published snapshot in one `Arc` store. A concurrent
/// reader therefore observes either the entire old roster or the entire new
/// one — never a partial, half-parsed, or empty roster.
///
/// `reload` is fail-closed: any parse error, or a roster that parses to zero
/// keys, leaves the previously published snapshot untouched and in force.
#[derive(Clone)]
pub struct RosterHandle {
    path: PathBuf,
    current: std::sync::Arc<Vec<MlDsaPublicKey>>,
    /// Maximum number of keys this handle will publish.  The handle refuses
    /// to load or publish a larger roster, so the hot-swap path cannot widen
    /// the roster past the bound the server was configured with.
    max_roster_size: usize,
}

impl RosterHandle {
    /// Load `path` and hold it. Fails closed at startup on a missing or
    /// malformed roster — the server never starts with no trusted clients.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        Self::load_with_limit(path, MAX_ROSTER_SIZE)
    }

    /// Load `path` with an explicit size limit (a deployment that raised the
    /// server's roster bound uses the same bound here).
    pub fn load_with_limit(path: &Path, max_roster_size: usize) -> Result<Self, IdentityError> {
        let roster = load_roster_with_limit(path, max_roster_size)?;
        Ok(Self {
            path: path.to_path_buf(),
            current: std::sync::Arc::new(roster),
            max_roster_size,
        })
    }

    /// The path this handle reloads from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The currently published roster.
    ///
    /// The returned `Arc` is an immutable snapshot: it keeps the old roster
    /// alive for any reader still holding it, which is what makes the swap
    /// safe without a lock on the read path.
    pub fn snapshot(&self) -> std::sync::Arc<Vec<MlDsaPublicKey>> {
        std::sync::Arc::clone(&self.current)
    }

    /// Number of keys in the published roster.
    pub fn len(&self) -> usize {
        self.current.len()
    }

    /// True when the published roster is empty.  Only ever true for a handle
    /// built from a roster that was non-empty, so this is false in practice —
    /// it exists so the emptiness case is observable rather than assumed.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }

    /// Re-read the backing file and, if it parses to a non-empty roster,
    /// publish it as the new snapshot.
    ///
    /// Returns the new roster length on success. On any failure the previous
    /// snapshot stays in force and the error is returned to the caller: a
    /// half-written or corrupt roster can never narrow the trusted set.
    pub fn reload(&mut self) -> Result<usize, IdentityError> {
        let parsed = load_roster_with_limit(&self.path, self.max_roster_size)?;
        if parsed.is_empty() {
            return Err(IdentityError::EmptyRoster {
                path: self.path.clone(),
            });
        }
        let len = parsed.len();
        // Single publication point: one store of a fully-built Arc. Readers
        // see the old snapshot until this line and the new one after it.
        self.current = std::sync::Arc::new(parsed);
        Ok(len)
    }
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

    // -----------------------------------------------------------------------
    // Roster-size bound
    // -----------------------------------------------------------------------

    /// The provisioning limit is the core's default roster bound — the
    /// server verifies the client signature against the *entire* roster with
    /// no early exit (D12), so the roster size bounds the server's
    /// per-handshake work.  The value is written out, not derived from the
    /// constant, so a change to the constant fails this test.
    #[test]
    fn roster_limit_is_64_and_matches_the_core_default() {
        assert_eq!(MAX_ROSTER_SIZE, 64);
        assert_eq!(
            MAX_ROSTER_SIZE,
            HandshakeV2ServerConfig::DEFAULT_MAX_ROSTER_SIZE
        );
    }

    /// `n` distinct ML-DSA-65 public keys.
    fn roster_keys(n: usize) -> Vec<MlDsaPublicKey> {
        (0..n)
            .map(|_| MlDsaKeypair::generate().expect("keygen").public_key())
            .collect()
    }

    /// Write a roster file with `n` payload lines of the given text (used to
    /// write files the writer itself would refuse to produce).
    fn write_roster_lines(path: &Path, lines: &[String]) {
        let mut content = String::from("PQTI\nversion: 1\ntype: roster\n");
        for l in lines {
            content.push_str(l);
            content.push('\n');
        }
        fs::write(path, content).expect("write");
    }

    /// A roster of exactly the limit loads.
    #[test]
    fn roster_at_the_limit_loads() {
        let path = temp_path("roster-at-limit");
        let keys = roster_keys(MAX_ROSTER_SIZE);
        save_roster(&path, &keys).expect("save roster at the limit");

        let loaded = load_roster(&path).expect("load roster at the limit");
        assert_eq!(loaded.len(), MAX_ROSTER_SIZE);
        assert_eq!(loaded[0].encode(), keys[0].encode());
        cleanup(&path);
    }

    /// One key over the limit is rejected — the load fails closed.
    #[test]
    fn roster_one_over_the_limit_is_rejected() {
        let path = temp_path("roster-over-limit");
        let keys = roster_keys(MAX_ROSTER_SIZE + 1);
        let lines: Vec<String> = keys.iter().map(|k| encode_hex(&k.encode())).collect();
        write_roster_lines(&path, &lines);

        let err = load_roster(&path).expect_err("an over-limit roster must be rejected");
        match err {
            IdentityError::RosterTooLarge { got, max, .. } => {
                assert_eq!(got, MAX_ROSTER_SIZE + 1);
                assert_eq!(max, MAX_ROSTER_SIZE);
            }
            other => panic!("unexpected error: {other}"),
        }
        cleanup(&path);
    }

    /// The size check runs *before* any key is decoded: a file with too many
    /// (malformed) lines must report the size, not a hex/parse error.  A
    /// hostile or corrupt file therefore cannot force an unbounded number of
    /// ML-DSA-65 key decodes.
    #[test]
    fn roster_over_the_limit_is_rejected_before_any_key_is_decoded() {
        let path = temp_path("roster-over-limit-malformed");
        let lines: Vec<String> = (0..=MAX_ROSTER_SIZE)
            .map(|_| "not-hex".to_string())
            .collect();
        write_roster_lines(&path, &lines);

        let err = load_roster(&path).expect_err("an over-limit roster must be rejected");
        assert!(
            matches!(err, IdentityError::RosterTooLarge { .. }),
            "the size check must precede decoding, got: {err}"
        );
        cleanup(&path);
    }

    /// The writer refuses to produce a file the loader would reject, and
    /// writes nothing.
    #[test]
    fn save_roster_over_the_limit_is_rejected_and_writes_nothing() {
        let path = temp_path("roster-save-over-limit");
        let keys = roster_keys(MAX_ROSTER_SIZE + 1);
        let err = save_roster(&path, &keys).expect_err("an over-limit roster must not be written");
        assert!(
            matches!(err, IdentityError::RosterTooLarge { .. }),
            "unexpected error: {err}"
        );
        assert!(
            !path.exists(),
            "a refused roster must not leave a file behind"
        );
    }

    /// The append path refuses to grow a full roster and leaves the file
    /// untouched.
    #[test]
    fn append_roster_at_the_limit_is_rejected_and_leaves_the_file_unchanged() {
        let path = temp_path("roster-append-at-limit");
        let keys = roster_keys(MAX_ROSTER_SIZE);
        save_roster(&path, &keys).expect("save roster at the limit");
        let before = fs::read(&path).expect("read");

        let extra = MlDsaKeypair::generate().expect("keygen").public_key();
        let err = append_roster(&path, &extra).expect_err("a full roster must not grow");
        assert!(
            matches!(err, IdentityError::RosterTooLarge { .. }),
            "unexpected error: {err}"
        );
        assert_eq!(
            fs::read(&path).expect("read"),
            before,
            "a refused append must not modify the file"
        );
        cleanup(&path);
    }

    /// End-to-end: the parser's limit and the core's effective limit are the
    /// same number, so a roster that the parser accepts is one the server
    /// will use, and one it rejects is one the server refuses.
    #[test]
    fn parser_limit_and_core_limit_agree() {
        let (client_id, server_id) = (
            MlDsaKeypair::generate().expect("keygen"),
            MlDsaKeypair::generate().expect("keygen"),
        );
        let at_limit = roster_keys(MAX_ROSTER_SIZE);
        let over_limit = roster_keys(MAX_ROSTER_SIZE + 1);

        let accepted = HandshakeV2ServerConfig::new(server_id.clone(), at_limit.clone());
        assert_eq!(
            accepted.roster.len(),
            MAX_ROSTER_SIZE,
            "a roster the parser accepts must be adopted by the core"
        );

        let refused = HandshakeV2ServerConfig::new(server_id, over_limit);
        assert!(
            refused.roster.is_empty(),
            "a roster the parser refuses must not be adopted by the core"
        );
        let _ = client_id;
    }
}
