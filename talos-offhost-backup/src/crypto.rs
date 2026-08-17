//! Client-side `age` encryption, passphrase (scrypt) recipient.
//!
//! # Why the LIBRARY and not the `age` CLI
//!
//! Not a preference — the CLI cannot do this. `age -p` reads the passphrase
//! from `/dev/tty`, and where there is no tty it falls back to `/dev/stdin`
//! and then fails with `ENOTTY` from `term.ReadPassword`. There is no
//! `--passphrase-file`, no `AGE_PASSPHRASE`, no stdin form. A scheduled,
//! unattended encrypt through the CLI is therefore impossible without a pty
//! wrapper, and putting a pty wrapper on the disaster-recovery path is a
//! worse trade than a library dependency.
//!
//! **The output is a standard age file.** `age -d archive.age`, typing the
//! escrowed passphrase, opens it. That property is the one that actually
//! matters: recovery must not depend on this workspace compiling, on a
//! toolchain, or on this crate still existing. It is asserted below by
//! pinning the file's magic header, which is the wire contract the CLI
//! reads.
//!
//! # Why the dump is not "safe because the columns are encrypted"
//!
//! `pg_dump --format=custom` carries the ciphertext columns AND the
//! plaintext ones — workflow names, module source, `graph_json`, schedule
//! definitions. Handing that to a third-party object store unencrypted
//! publishes all of it. The DEK-encrypted columns are irrelevant to this
//! decision; the plaintext ones are the whole reason `age` is here.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use age::secrecy::SecretString;

/// The first bytes of every age v1 file. Pinned so a change of encryption
/// scheme cannot happen silently — an archive the stock `age` CLI cannot
/// open is not a backup.
pub const AGE_V1_MAGIC: &[u8] = b"age-encryption.org/v1\n";

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("could not read '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("could not write '{path}': {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    /// Deliberately vague about WHY. A decrypt failure is almost always the
    /// wrong passphrase, and an error that distinguishes "wrong passphrase"
    /// from "corrupt header" gives an attacker holding the ciphertext an
    /// oracle. The operator gets the actionable half in the caller's
    /// message; the crypto layer does not elaborate.
    #[error("age decryption failed — wrong passphrase, or the archive is not a valid age file")]
    Decrypt,
    #[error("age encryption failed: {0}")]
    Encrypt(String),
}

/// Encrypt `plaintext` to `out`, passphrase (scrypt) recipient.
///
/// Streams: a 400 MB dump is never held in memory, on a host whose backup
/// sidecars are capped at 256 MB for exactly this reason.
pub fn encrypt_file(
    passphrase: &SecretString,
    plaintext: &Path,
    out: &Path,
) -> Result<u64, CryptoError> {
    let mut src = BufReader::new(File::open(plaintext).map_err(|e| CryptoError::Read {
        path: plaintext.display().to_string(),
        source: e,
    })?);
    let dst = File::create(out).map_err(|e| CryptoError::Write {
        path: out.display().to_string(),
        source: e,
    })?;

    let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
    let mut writer = encryptor
        .wrap_output(dst)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    let n = io::copy(&mut src, &mut writer).map_err(|e| CryptoError::Write {
        path: out.display().to_string(),
        source: e,
    })?;
    writer
        .finish()
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?
        .flush()
        .map_err(|e| CryptoError::Write {
            path: out.display().to_string(),
            source: e,
        })?;
    Ok(n)
}

/// Decrypt `ciphertext` to `out`.
///
/// A wrong passphrase MUST reach the caller as an error. The restore drill
/// turns this into a hard failure, because a drill that "passed" without
/// decrypting anything proves nothing — that is the entire lesson of the
/// 2026-08-03 run.
pub fn decrypt_file(
    passphrase: &SecretString,
    ciphertext: &Path,
    out: &Path,
) -> Result<u64, CryptoError> {
    let src = BufReader::new(File::open(ciphertext).map_err(|e| CryptoError::Read {
        path: ciphertext.display().to_string(),
        source: e,
    })?);
    let identity = age::scrypt::Identity::new(passphrase.clone());
    let decryptor = age::Decryptor::new_buffered(src).map_err(|_| CryptoError::Decrypt)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| CryptoError::Decrypt)?;

    let mut dst = File::create(out).map_err(|e| CryptoError::Write {
        path: out.display().to_string(),
        source: e,
    })?;
    // NOT `io::copy` straight through: an authentication failure surfaces
    // mid-stream (age authenticates per 64 KiB chunk), and a plain copy
    // would leave a partially-written plaintext behind that looks like a
    // successful restore input. Copy, then only on success does the caller
    // use the file — and on error the partial output is removed.
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                drop(dst);
                let _ = std::fs::remove_file(out);
                return Err(CryptoError::Decrypt);
            }
        };
        dst.write_all(&buf[..n]).map_err(|e| CryptoError::Write {
            path: out.display().to_string(),
            source: e,
        })?;
        total += n as u64;
    }
    dst.flush().map_err(|e| CryptoError::Write {
        path: out.display().to_string(),
        source: e,
    })?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "talos-offhost-crypto-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn pass(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn round_trip_recovers_the_exact_bytes() {
        let d = tmpdir("rt");
        let plain = d.join("pg.dump");
        // Binary, not text: a pg_dump custom archive is binary and a
        // text-only test would not catch an encoding bug.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&plain, &payload).unwrap();

        let enc = d.join("pg.age");
        let n = encrypt_file(&pass("correct horse battery staple"), &plain, &enc).unwrap();
        assert_eq!(n, payload.len() as u64);

        let back = d.join("pg.out");
        decrypt_file(&pass("correct horse battery staple"), &enc, &back).unwrap();
        assert_eq!(fs::read(&back).unwrap(), payload);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        // The whole reason `age` is on this path: the dump carries plaintext
        // workflow names, module source and graph_json alongside the
        // DEK-encrypted columns.
        let d = tmpdir("leak");
        let plain = d.join("pg.dump");
        fs::write(&plain, b"CREATE TABLE workflows; secret-workflow-name-42").unwrap();
        let enc = d.join("pg.age");
        encrypt_file(&pass("pw"), &plain, &enc).unwrap();
        let bytes = fs::read(&enc).unwrap();
        assert!(!bytes
            .windows(24)
            .any(|w| w == b"secret-workflow-name-42\0"[..24].to_vec().as_slice()));
        let hay = String::from_utf8_lossy(&bytes);
        assert!(!hay.contains("secret-workflow-name-42"));
        assert!(!hay.contains("CREATE TABLE"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_passphrase_is_not_in_the_ciphertext() {
        let d = tmpdir("pw");
        let plain = d.join("x");
        fs::write(&plain, b"hello").unwrap();
        let enc = d.join("x.age");
        encrypt_file(&pass("hunter2-unique-marker"), &plain, &enc).unwrap();
        let hay = String::from_utf8_lossy(&fs::read(&enc).unwrap()).to_string();
        assert!(!hay.contains("hunter2-unique-marker"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn wrong_passphrase_fails_and_leaves_no_partial_plaintext() {
        // THE drill leg. A restore that "succeeded" with the wrong key would
        // certify an unreadable bucket.
        let d = tmpdir("wrong");
        let plain = d.join("x");
        fs::write(&plain, vec![7u8; 300_000]).unwrap();
        let enc = d.join("x.age");
        encrypt_file(&pass("right"), &plain, &enc).unwrap();

        let out = d.join("x.out");
        let e = decrypt_file(&pass("wrong"), &enc, &out).unwrap_err();
        assert!(matches!(e, CryptoError::Decrypt), "{e:?}");
        assert!(
            !out.exists() || fs::read(&out).unwrap().is_empty(),
            "a failed decrypt must not leave a partial plaintext that looks restorable"
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_truncated_archive_fails_rather_than_yielding_short_data() {
        // The single-file-bind-mount truncation class (#626) as it would
        // appear here: current bytes, clamped to an old length. age
        // authenticates per chunk, so this must be an error and not a
        // shorter-but-plausible plaintext.
        let d = tmpdir("trunc");
        let plain = d.join("x");
        fs::write(&plain, vec![3u8; 500_000]).unwrap();
        let enc = d.join("x.age");
        encrypt_file(&pass("pw"), &plain, &enc).unwrap();
        let mut bytes = fs::read(&enc).unwrap();
        bytes.truncate(bytes.len() / 2);
        fs::write(&enc, &bytes).unwrap();

        let out = d.join("x.out");
        assert!(decrypt_file(&pass("pw"), &enc, &out).is_err());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_flipped_ciphertext_byte_is_detected() {
        let d = tmpdir("flip");
        let plain = d.join("x");
        fs::write(&plain, vec![9u8; 100_000]).unwrap();
        let enc = d.join("x.age");
        encrypt_file(&pass("pw"), &plain, &enc).unwrap();
        let mut bytes = fs::read(&enc).unwrap();
        let last = bytes.len() - 5;
        bytes[last] ^= 0xff;
        fs::write(&enc, &bytes).unwrap();

        let out = d.join("x.out");
        assert!(decrypt_file(&pass("pw"), &enc, &out).is_err());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn output_is_a_standard_age_v1_file() {
        // The disaster-recovery contract: `age -d` must open this without
        // this workspace, this crate, or a Rust toolchain. Pinning the magic
        // is how that survives a dependency bump.
        let d = tmpdir("magic");
        let plain = d.join("x");
        fs::write(&plain, b"hi").unwrap();
        let enc = d.join("x.age");
        encrypt_file(&pass("pw"), &plain, &enc).unwrap();
        let bytes = fs::read(&enc).unwrap();
        assert!(
            bytes.starts_with(AGE_V1_MAGIC),
            "not an age v1 file — `age -d` will not open it"
        );
        // The scrypt (passphrase) recipient stanza, not an X25519 one: a
        // silent switch to a keypair would make the escrowed passphrase
        // useless.
        let head = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).to_string();
        assert!(
            head.contains("-> scrypt"),
            "not a passphrase recipient: {head}"
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_empty_input_still_round_trips() {
        let d = tmpdir("empty");
        let plain = d.join("x");
        fs::write(&plain, b"").unwrap();
        let enc = d.join("x.age");
        assert_eq!(encrypt_file(&pass("pw"), &plain, &enc).unwrap(), 0);
        let out = d.join("x.out");
        assert_eq!(decrypt_file(&pass("pw"), &enc, &out).unwrap(), 0);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn decrypting_a_non_age_file_is_an_error_not_a_passthrough() {
        let d = tmpdir("notage");
        let junk = d.join("plain.dump");
        fs::write(&junk, b"PGDMP not encrypted at all").unwrap();
        let out = d.join("out");
        assert!(decrypt_file(&pass("pw"), &junk, &out).is_err());
        fs::remove_dir_all(&d).ok();
    }
}
