//! `pq-tunnel keygen` — identity key generation for out-of-band provisioning.
//!
//! Generates a fresh ML-DSA-65 key pair, writes the secret seed and public key
//! as versioned provisioning files (see [`crate::identity`]), optionally
//! appends the public key to a server roster, and prints a short fingerprint
//! for verification. Never prints or logs the seed.

use std::path::{Component, Path, PathBuf};

use pq_crypto::MlDsaKeypair;

use crate::{KeygenArgs, identity};

/// Run the keygen command.
///
/// Fails closed: an existing output file is never silently replaced without
/// `--force` (kernel-enforced O_EXCL, not a pre-check), and no two outputs may
/// be the same file (writing the public key over the identity would destroy
/// the only copy of the seed).
pub fn run(args: &KeygenArgs) -> Result<(), Box<dyn std::error::Error>> {
    check_distinct(
        &args.identity,
        &args.public_key,
        "--identity",
        "--public-key",
    )?;
    if let Some(roster_path) = &args.append_roster {
        check_distinct(&args.identity, roster_path, "--identity", "--append-roster")?;
        check_distinct(
            &args.public_key,
            roster_path,
            "--public-key",
            "--append-roster",
        )?;
    }

    if !args.force {
        identity::ensure_missing(&args.identity)
            .map_err(|e| format!("{e} (pass --force to overwrite)"))?;
        identity::ensure_missing(&args.public_key)
            .map_err(|e| format!("{e} (pass --force to overwrite)"))?;
    }

    let keypair = MlDsaKeypair::generate().map_err(|e| format!("key generation failed: {e}"))?;

    identity::save_identity(&args.identity, &keypair)?;
    let public = keypair.public_key();
    identity::save_public_key(&args.public_key, &public)?;
    if let Some(roster_path) = &args.append_roster {
        identity::append_roster(roster_path, &public)?;
    }

    println!("generated identity:      {}", args.identity.display());
    println!("public key written to:   {}", args.public_key.display());
    if let Some(roster_path) = &args.append_roster {
        println!("appended to roster:      {}", roster_path.display());
    }
    println!(
        "fingerprint:             {}",
        identity::fingerprint(&public)
    );
    println!("distribute the public key file to peers; keep the identity file secret.");
    Ok(())
}

/// Reject two output paths resolving to the same file.
///
/// Paths are normalized (absolute, `..` collapsed) and compared
/// case-insensitively on Windows. Applies even with `--force`: writing the
/// public key over the identity file would silently discard the seed.
fn check_distinct(
    a: &Path,
    b: &Path,
    flag_a: &str,
    flag_b: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let na = normalize(a);
    let nb = normalize(b);
    let same = if cfg!(windows) {
        na.to_string_lossy().to_lowercase() == nb.to_string_lossy().to_lowercase()
    } else {
        na == nb
    };
    if same {
        return Err(format!(
            "{flag_a} and {flag_b} resolve to the same file {}; refusing to overwrite the identity with key material",
            na.display()
        )
        .into());
    }
    Ok(())
}

fn normalize(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pq-tunnel-keygen-{}-{}", name, std::process::id()))
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn keygen_writes_identity_and_public_key() {
        let id = temp_path("gen-id");
        let pk = temp_path("gen-pk");

        let keygen = KeygenArgs {
            identity: id.clone(),
            public_key: pk.clone(),
            append_roster: None,
            force: false,
        };
        run(&keygen).expect("keygen");

        assert!(id.exists(), "identity file must exist");
        assert!(pk.exists(), "public key file must exist");
        let loaded = identity::load_identity(&id).expect("load identity");
        assert_eq!(loaded.public_key().encode().len(), 1952);
        cleanup(&id);
        cleanup(&pk);
    }

    #[test]
    fn keygen_refuses_to_overwrite_identity() {
        let id = temp_path("gen-nooverwrite");
        let pk = temp_path("gen-pk2");
        fs::write(&id, "keep me").expect("seed file");

        let keygen = KeygenArgs {
            identity: id.clone(),
            public_key: pk.clone(),
            append_roster: None,
            force: false,
        };
        let err = run(&keygen).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected: {err}"
        );
        assert!(
            err.to_string().contains("force"),
            "expected a --force hint: {err}"
        );
        assert_eq!(fs::read_to_string(&id).unwrap(), "keep me");
        cleanup(&id);
        cleanup(&pk);
    }

    #[test]
    fn keygen_rejects_colliding_outputs() {
        let same = temp_path("gen-collide");

        let keygen = KeygenArgs {
            identity: same.clone(),
            public_key: same.clone(),
            append_roster: None,
            force: false,
        };
        let err = run(&keygen).unwrap_err();
        assert!(err.to_string().contains("same file"), "unexpected: {err}");
        cleanup(&same);

        // Same collision but via --force as well: the seed must never be
        // silently destroyed by writing the public key over it.
        let keygen = KeygenArgs {
            identity: same.clone(),
            public_key: same.clone(),
            append_roster: None,
            force: true,
        };
        assert!(run(&keygen).is_err());
        cleanup(&same);
    }

    #[test]
    fn keygen_force_overwrites_identity() {
        let id = temp_path("gen-force");
        let pk = temp_path("gen-pk3");
        fs::write(&id, "old").expect("seed file");

        let keygen = KeygenArgs {
            identity: id.clone(),
            public_key: pk.clone(),
            append_roster: None,
            force: true,
        };
        run(&keygen).expect("keygen with --force");
        assert!(
            identity::load_identity(&id).is_ok(),
            "overwritten file must load"
        );
        cleanup(&id);
        cleanup(&pk);
    }

    #[test]
    fn keygen_append_roster_registers_key() {
        let id = temp_path("gen-idr");
        let pk = temp_path("gen-pkr");
        let roster = temp_path("gen-roster");

        let keygen = KeygenArgs {
            identity: id.clone(),
            public_key: pk.clone(),
            append_roster: Some(roster.clone()),
            force: false,
        };
        run(&keygen).expect("keygen with roster append");

        let roster_keys = identity::load_roster(&roster).expect("roster");
        assert_eq!(roster_keys.len(), 1);
        let identity_keys = identity::load_identity(&id).expect("identity");
        assert_eq!(
            roster_keys[0].encode(),
            identity_keys.public_key().encode(),
            "roster must contain the generated key"
        );
        cleanup(&id);
        cleanup(&pk);
        cleanup(&roster);
    }
}
