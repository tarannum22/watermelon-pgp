//! Interoperability with GnuPG, in both directions.
//!
//! Requires `gpg` on PATH. Skipped (with a message) when it is missing, unless
//! `WATERMELON_REQUIRE_GPG=1` is set, which CI does.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use watermelon_pgp_core::crypto::{
    self, Algorithm, Cert, Container, EncryptOptions, SignatureCheck, SignedSecretKey,
};

const PASSPHRASE: &str = "interop-test-passphrase";

struct Gpg {
    home: tempfile::TempDir,
}

impl Gpg {
    fn new() -> Option<Self> {
        if Command::new("gpg").arg("--version").output().is_err() {
            assert!(
                std::env::var("WATERMELON_REQUIRE_GPG").is_err(),
                "gpg is required but not installed"
            );
            eprintln!("gpg not found, skipping GnuPG interop tests");
            return None;
        }
        Some(Self {
            home: tempfile::tempdir().unwrap(),
        })
    }

    fn run(&self, args: &[&str], stdin: &[u8]) -> Vec<u8> {
        self.try_run(args, stdin)
            .unwrap_or_else(|stderr| panic!("gpg {args:?} failed: {stderr}"))
    }

    /// Like [`Self::run`], returning gpg's stderr on failure instead of panicking.
    fn try_run(&self, args: &[&str], stdin: &[u8]) -> Result<Vec<u8>, String> {
        let mut child = Command::new("gpg")
            .arg("--homedir")
            .arg(self.home.path())
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                PASSPHRASE,
                "--trust-model",
                "always",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Feed stdin from another thread: gpg may start writing output before it has read all
        // input, and filling both pipes from one thread deadlocks.
        let mut child_stdin = child.stdin.take().unwrap();
        let input = stdin.to_vec();
        let writer = std::thread::spawn(move || child_stdin.write_all(&input));
        let out = child.wait_with_output().unwrap();
        // A write error only means gpg exited early; its stderr explains why.
        let _ = writer.join().unwrap();
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }

    /// Generate a key in GnuPG and return its exported secret key (passphrase-protected).
    /// `algo` is `"rsa4096"` or `"future-default"`; RSA keys get a separate encryption subkey,
    /// the way partners' RSA keys usually look.
    fn generate(&self, uid: &str, algo: &str) -> Vec<u8> {
        if algo == "rsa4096" {
            self.run(
                &["--quick-generate-key", uid, algo, "cert,sign", "never"],
                b"",
            );
            let listing =
                String::from_utf8(self.run(&["--with-colons", "--list-keys", uid], b"")).unwrap();
            let fpr = listing
                .lines()
                .find_map(|line| line.strip_prefix("fpr:::::::::"))
                .unwrap()
                .trim_end_matches(':')
                .to_owned();
            self.run(&["--quick-add-key", &fpr, algo, "encr", "never"], b"");
        } else {
            self.run(
                &["--quick-generate-key", uid, algo, "default", "never"],
                b"",
            );
        }
        self.run(&["--armor", "--export-secret-keys", uid], b"")
    }
}

fn plaintext() -> Vec<u8> {
    b"customer_id,email,amount\n42,alice@example.com,13.37\n".repeat(5000)
}

/// Curve25519 keys are generated fresh; the (slow) RSA key is generated once per test binary.
fn our_key(uid: &str, algorithm: Algorithm) -> SignedSecretKey {
    static RSA: std::sync::OnceLock<SignedSecretKey> = std::sync::OnceLock::new();
    match algorithm {
        Algorithm::Curve25519 => crypto::generate(uid, algorithm).unwrap(),
        Algorithm::Rsa4096 => RSA
            .get_or_init(|| {
                crypto::generate("Watermelon RSA <rsa@example.com>", algorithm).unwrap()
            })
            .clone(),
    }
}

fn import_unlocked(data: &[u8]) -> Cert {
    let mut certs = crypto::parse_certs(data).unwrap();
    assert_eq!(certs.len(), 1);
    let mut cert = certs.remove(0);
    cert.unlock(PASSPHRASE).unwrap();
    cert
}

/// We encrypt and sign; GnuPG decrypts and verifies.
fn watermelon_to_gpg(gpg: &Gpg, algorithm: Algorithm, container: Container, armor: bool) {
    let uid = format!("wm-{algorithm:?}-{container:?}-{armor}@example.com");
    let gpg_secret = gpg.generate(
        &uid,
        if algorithm == Algorithm::Rsa4096 {
            "rsa4096"
        } else {
            "future-default"
        },
    );
    let recipient = import_unlocked(&gpg_secret).public();

    let signer = our_key(
        "Watermelon Sender <sender@example.com>",
        Algorithm::Curve25519,
    );
    gpg.run(
        &["--import"],
        crypto::armor_public(&signer.to_public_key())
            .unwrap()
            .as_bytes(),
    );

    let mut encrypted = Vec::new();
    crypto::encrypt(
        &plaintext()[..],
        &mut encrypted,
        &EncryptOptions {
            recipients: &[recipient],
            signer: Some(&signer),
            container,
            armor,
            file_name: "customers.csv",
        },
    )
    .unwrap();

    let status = tempfile::NamedTempFile::new().unwrap();
    let decrypted = gpg.run(
        &[
            "--status-file",
            status.path().to_str().unwrap(),
            "--decrypt",
        ],
        &encrypted,
    );
    assert_eq!(decrypted, plaintext());
    let status = std::fs::read_to_string(status.path()).unwrap();
    assert!(
        status.contains("GOODSIG"),
        "gpg did not verify signature:\n{status}"
    );
}

/// GnuPG encrypts and signs; we decrypt and verify.
fn gpg_to_watermelon(gpg: &Gpg, algorithm: Algorithm, armor: bool) {
    let ours = our_key(&format!("Watermelon {algorithm:?} {armor}"), algorithm);
    let recipient_fpr = crypto::fingerprint(&ours.to_public_key());
    gpg.run(
        &["--import"],
        crypto::armor_public(&ours.to_public_key())
            .unwrap()
            .as_bytes(),
    );

    let sender_uid = format!("gpg-sender-{algorithm:?}-{armor}@example.com");
    let sender = import_unlocked(&gpg.generate(&sender_uid, "future-default")).public();

    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), plaintext()).unwrap();
    let mut args = vec![
        "--local-user",
        &sender_uid,
        "--recipient",
        &recipient_fpr,
        "--sign",
        "--encrypt",
        "--output",
        "-",
    ];
    if armor {
        args.push("--armor");
    }
    args.push(input.path().to_str().unwrap());
    let encrypted = gpg.run(&args, b"");

    let mut decrypted = Vec::new();
    let check = crypto::decrypt(
        &encrypted[..],
        &mut decrypted,
        &[ours],
        std::slice::from_ref(&sender),
    )
    .unwrap();
    assert_eq!(decrypted, plaintext());
    assert_eq!(
        check,
        SignatureCheck::Valid {
            signer: crypto::fingerprint(&sender)
        }
    );
}

#[test]
fn watermelon_encrypts_gnupg_decrypts() {
    let Some(gpg) = Gpg::new() else { return };
    for algorithm in [Algorithm::Curve25519, Algorithm::Rsa4096] {
        for armor in [false, true] {
            watermelon_to_gpg(&gpg, algorithm, Container::SeipdV1, armor);
        }
    }
}

#[test]
fn gnupg_encrypts_watermelon_decrypts() {
    let Some(gpg) = Gpg::new() else { return };
    for algorithm in [Algorithm::Curve25519, Algorithm::Rsa4096] {
        for armor in [false, true] {
            gpg_to_watermelon(&gpg, algorithm, armor);
        }
    }
}

/// libgcrypt 1.12.0 (shipped with GnuPG 2.4.8 on Ubuntu 26.04) rejects most passphrase-protected
/// Curve25519 secret keys exported by rPGP with "Bad passphrase". The same exports work with
/// libgcrypt 1.11 and 1.12.4, and unprotected exports work on 1.12.0, so this is treated as an
/// upstream regression (likely https://dev.gnupg.org/T8080 / T8094). See README, Known issues.
fn has_libgcrypt_1_12_0_ecc_import_bug() -> bool {
    Command::new("gpg")
        .arg("--version")
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("libgcrypt 1.12.0"))
}

#[test]
fn gnupg_accepts_our_exported_secret_key() {
    let Some(gpg) = Gpg::new() else { return };
    for algorithm in [Algorithm::Curve25519, Algorithm::Rsa4096] {
        let ours = our_key(&format!("Exported {algorithm:?}"), algorithm);
        let armored = crypto::armor_secret(&ours, PASSPHRASE).unwrap();
        gpg.run(&["--import"], armored.as_bytes());

        let mut encrypted = Vec::new();
        crypto::encrypt(
            &b"hello"[..],
            &mut encrypted,
            &EncryptOptions {
                recipients: &[ours.to_public_key()],
                signer: None,
                container: Container::SeipdV1,
                armor: false,
                file_name: "f",
            },
        )
        .unwrap();
        match gpg.try_run(&["--decrypt"], &encrypted) {
            Ok(plaintext) => assert_eq!(plaintext, b"hello"),
            Err(stderr)
                if algorithm == Algorithm::Curve25519 && has_libgcrypt_1_12_0_ecc_import_bug() =>
            {
                eprintln!(
                    "KNOWN UPSTREAM ISSUE: libgcrypt 1.12.0 could not use our exported \
                     Curve25519 secret key (see README, Known issues):\n{stderr}"
                );
            }
            Err(stderr) => panic!("gpg could not use our exported {algorithm:?} key: {stderr}"),
        }
    }
}
