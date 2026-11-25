//! Processing one file: stream it through encryption or decryption into a hidden temp file in
//! the output folder, make it durable, then publish it under its final name without ever
//! overwriting an existing file. Nobody watching the output folder sees a partial file, and a
//! file that fails integrity or signature checks never appears there at all.

use std::{
    fmt,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

use crate::platform;
use sha2::{Digest, Sha256};
use watermelon_pgp_core::{
    crypto::{self, EncryptOptions, SignatureCheck, SignedPublicKey, SignedSecretKey},
    jobs::{JobKind, JobSpec, VerifyPolicy},
};

/// Extensions a decrypt job strips from the input name.
const ENCRYPTED_EXTENSIONS: &[&str] = &[".pgp", ".gpg", ".asc"];
const TEMP_SUFFIX: &str = ".watermelon-tmp";
/// A temp file nobody has written to for this long was left behind by a crash. Files being
/// written are touched continuously, so this never catches one in use.
pub const STALE_TEMP_AFTER: Duration = Duration::from_secs(15 * 60);

/// Key material a job needs, loaded once per polling pass.
#[derive(Default)]
pub struct JobKeys {
    pub recipients: Vec<SignedPublicKey>,
    pub signer: Option<SignedSecretKey>,
    pub decrypt: Vec<SignedSecretKey>,
    pub verifiers: Vec<SignedPublicKey>,
}

/// A successfully processed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Processed {
    pub output: PathBuf,
    /// SHA-256 of the input file.
    pub sha256: String,
    pub bytes: u64,
    /// Signature outcome for decrypt jobs that check signatures.
    pub signature: Option<String>,
}

/// Why a file wasn't processed.
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessError {
    /// Windows: another process has the input open for writing, such as an SFTP server still
    /// receiving it. Nothing was done; try again later.
    InUse,
    /// The file can't be processed; the message says why.
    Failed(String),
}

impl From<String> for ProcessError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InUse => f.write_str("in use by another process"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

/// Process `input` according to `spec`. On error nothing is left in the output folder.
pub fn process_file(
    spec: &JobSpec,
    keys: &JobKeys,
    input: &Path,
) -> Result<Processed, ProcessError> {
    let name = input
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("file name is not valid UTF-8: {}", input.display()))?;
    let output = spec.output_dir.join(output_name(spec, name));
    if output.exists() {
        return Err(format!("output {} already exists", output.display()).into());
    }

    let input_file = match platform::open_input(input) {
        Ok(file) => file,
        Err(e) if platform::is_in_use(&e) => return Err(ProcessError::InUse),
        Err(e) => return Err(format!("opening {}: {e}", input.display()).into()),
    };
    let mut reader = HashingReader::new(input_file);
    let temp =
        TempFile::create(&spec.output_dir, name).map_err(|e| format!("creating temp file: {e}"))?;
    let mut writer = BufWriter::new(temp.file());

    let signature = match spec.kind {
        JobKind::Encrypt => {
            crypto::encrypt(
                &mut reader,
                &mut writer,
                &EncryptOptions {
                    recipients: &keys.recipients,
                    signer: keys.signer.as_ref(),
                    container: spec.container,
                    armor: spec.armor,
                    file_name: name,
                },
            )
            .map_err(|e| e.to_string())?;
            None
        }
        JobKind::Decrypt => {
            let check = crypto::decrypt(
                BufReader::new(&mut reader),
                &mut writer,
                &keys.decrypt,
                &keys.verifiers,
            )
            .map_err(|e| e.to_string())?;
            signature_outcome(spec.verify_policy, check)?
        }
    };
    writer.flush().map_err(|e| format!("writing output: {e}"))?;
    drop(writer);

    let (sha256, bytes) = reader.finish();
    temp.publish(&output)?;
    Ok(Processed {
        output,
        sha256,
        bytes,
        signature,
    })
}

/// SHA-256 of a file, for auditing files that failed before they were fully read.
pub fn sha256_of(path: &Path) -> io::Result<String> {
    let mut reader = HashingReader::new(File::open(path)?);
    io::copy(&mut reader, &mut io::sink())?;
    Ok(reader.finish().0)
}

/// Move `file` into `dir` (created if needed), keeping its name unless that is taken.
/// Remove our temp files in `dir` that haven't been modified for `older_than`: leftovers of a
/// crash or power loss. They are hidden, but an SFTP pickup might still copy them.
pub fn remove_stale_temp_files(dir: &Path, older_than: Duration) -> io::Result<Vec<PathBuf>> {
    let now = SystemTime::now();
    let mut removed = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with('.') && name.ends_with(TEMP_SUFFIX)) {
            continue;
        }
        let meta = entry.metadata()?;
        let idle = meta
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok());
        if meta.file_type().is_file() && idle.is_some_and(|idle| idle >= older_than) {
            fs::remove_file(entry.path())?;
            removed.push(entry.path());
        }
    }
    Ok(removed)
}

pub fn move_into(file: &Path, dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let name = file
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut target = dir.join(name);
    let mut n = 1;
    loop {
        match platform::move_no_replace(file, &target) {
            Ok(()) => return Ok(target),
            // Taken (also by a file that appeared since we looked): try the next name.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                target = dir.join(format!("{}.{n}", name.to_string_lossy()));
                n += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn output_name(spec: &JobSpec, input_name: &str) -> String {
    match spec.kind {
        JobKind::Encrypt => format!("{input_name}{}", spec.output_extension()),
        JobKind::Decrypt => {
            let lower = input_name.to_ascii_lowercase();
            ENCRYPTED_EXTENSIONS
                .iter()
                .find(|ext| lower.ends_with(*ext) && input_name.len() > ext.len())
                .map(|ext| input_name[..input_name.len() - ext.len()].to_owned())
                .unwrap_or_else(|| input_name.to_owned())
        }
    }
}

fn signature_outcome(
    policy: VerifyPolicy,
    check: SignatureCheck,
) -> Result<Option<String>, String> {
    let problem = match check {
        SignatureCheck::Valid { signer } => return Ok(Some(format!("signed by {signer}"))),
        SignatureCheck::Unsigned => "not signed",
        SignatureCheck::Unverified => "signature not from a configured sender key",
    };
    match policy {
        VerifyPolicy::Ignore => Ok(None),
        VerifyPolicy::Warn => Ok(Some(format!("WARNING: {problem}"))),
        VerifyPolicy::Require => Err(format!("signature required but {problem}")),
    }
}

/// A hidden file in the output folder that is deleted unless published.
struct TempFile {
    path: PathBuf,
    file: File,
    published: bool,
}

impl TempFile {
    fn create(dir: &Path, name: &str) -> io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = dir.join(format!(".{name}.{unique}{TEMP_SUFFIX}"));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self {
            path,
            file,
            published: false,
        })
    }

    fn file(&self) -> &File {
        &self.file
    }

    /// Make the content durable and give it its final name, refusing to overwrite.
    fn publish(mut self, target: &Path) -> Result<(), String> {
        self.file
            .sync_all()
            .map_err(|e| format!("syncing output: {e}"))?;
        // A hard link fails if the target exists, which makes "never overwrite" atomic.
        // Filesystems without hard links fall back to a move that refuses an existing target
        // (atomically on Windows).
        match fs::hard_link(&self.path, target) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(format!("output {} already exists", target.display()));
            }
            Err(_) => {
                platform::move_no_replace(&self.path, target).map_err(|e| {
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        format!("output {} already exists", target.display())
                    } else {
                        format!("publishing {}: {e}", target.display())
                    }
                })?;
                self.published = true;
            }
        }
        sync_dir(target.parent().unwrap_or(Path::new(".")));
        Ok(())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        // After a hard-link publish the temp name is still there and is removed here too.
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Persist a directory entry change. Best effort: not every platform supports it.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = File::open(dir) {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Hashes everything read through it.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> (String, u64) {
        (hex::encode(self.hasher.finalize()), self.bytes)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        BYTES_READ.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
}

/// Bytes read from input files by every job in this process so far.
static BYTES_READ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many bytes of input files jobs have read so far, in this process. It keeps growing while
/// a file is being processed, so a stopping service can tell progress from a hang.
pub fn bytes_read() -> u64 {
    BYTES_READ.load(std::sync::atomic::Ordering::Relaxed)
}

impl<R> fmt::Debug for HashingReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashingReader")
            .field("bytes", &self.bytes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use watermelon_pgp_core::crypto::{Algorithm, Container};

    struct Dirs {
        _root: tempfile::TempDir,
        input: PathBuf,
        output: PathBuf,
    }

    fn dirs() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("in");
        let output = root.path().join("out");
        fs::create_dir(&input).unwrap();
        fs::create_dir(&output).unwrap();
        Dirs {
            _root: root,
            input,
            output,
        }
    }

    fn spec(kind: JobKind, d: &Dirs) -> JobSpec {
        JobSpec::new("t", kind, &d.input, &d.output)
    }

    fn output_entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Reading input counts as progress for a stopping service.
    #[test]
    fn reading_input_counts_bytes() {
        let d = dirs();
        let file = d.input.join("data.csv");
        fs::write(&file, vec![b'x'; 10_000]).unwrap();
        let before = bytes_read();
        sha256_of(&file).unwrap();
        // Other tests may read at the same time: at least this file's bytes.
        assert!(bytes_read() - before >= 10_000);
    }

    #[test]
    fn stale_temp_files_from_a_crash_are_removed() {
        let d = dirs();
        let hour_ago = SystemTime::now() - Duration::from_secs(3600);
        let make = |name: &str, modified: SystemTime| {
            let file = File::create(d.output.join(name)).unwrap();
            file.set_modified(modified).unwrap();
        };
        make(".a.csv.4242-0.watermelon-tmp", hour_ago);
        make(".b.csv.4242-1.watermelon-tmp", SystemTime::now());
        make(".profile", hour_ago);
        make("report.watermelon-tmp", hour_ago);

        let removed = remove_stale_temp_files(&d.output, STALE_TEMP_AFTER).unwrap();
        assert_eq!(removed, vec![d.output.join(".a.csv.4242-0.watermelon-tmp")]);
        let mut left: Vec<_> = fs::read_dir(&d.output)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                ".b.csv.4242-1.watermelon-tmp",
                ".profile",
                "report.watermelon-tmp"
            ],
            "files in use and other people's files are left alone"
        );
    }

    #[test]
    fn output_names() {
        let d = dirs();
        let mut enc = spec(JobKind::Encrypt, &d);
        assert_eq!(output_name(&enc, "a.csv"), "a.csv.pgp");
        enc.armor = true;
        assert_eq!(output_name(&enc, "a.csv"), "a.csv.asc");
        enc.extension = Some(".gpg".into());
        assert_eq!(output_name(&enc, "a.csv"), "a.csv.gpg");
        let dec = spec(JobKind::Decrypt, &d);
        assert_eq!(output_name(&dec, "a.csv.PGP"), "a.csv");
        assert_eq!(output_name(&dec, "a.csv.asc"), "a.csv");
        assert_eq!(output_name(&dec, "a.csv"), "a.csv");
        assert_eq!(output_name(&dec, ".pgp"), ".pgp");
    }

    #[test]
    fn encrypt_then_decrypt_with_signature_policy() {
        let d = dirs();
        let ours = crypto::generate("Ours", Algorithm::Curve25519).unwrap();
        let partner = crypto::generate("Partner", Algorithm::Curve25519).unwrap();
        let plaintext = b"id,amount\n1,10\n".repeat(10_000);
        fs::write(d.input.join("report.csv"), &plaintext).unwrap();

        let enc_keys = JobKeys {
            recipients: vec![partner.to_public_key()],
            signer: Some(ours.clone()),
            ..Default::default()
        };
        let done = process_file(
            &spec(JobKind::Encrypt, &d),
            &enc_keys,
            &d.input.join("report.csv"),
        )
        .unwrap();
        assert_eq!(done.output, d.output.join("report.csv.pgp"));
        assert_eq!(done.bytes, plaintext.len() as u64);
        assert_eq!(done.sha256, sha256_of(&d.input.join("report.csv")).unwrap());
        assert_eq!(
            output_entries(&d.output),
            ["report.csv.pgp"],
            "no temp files left"
        );

        // Partner decrypts it, requiring our signature.
        let d2 = dirs();
        fs::copy(&done.output, d2.input.join("report.csv.pgp")).unwrap();
        let mut dec = spec(JobKind::Decrypt, &d2);
        dec.verify_policy = VerifyPolicy::Require;
        let dec_keys = JobKeys {
            decrypt: vec![partner.clone()],
            verifiers: vec![ours.to_public_key()],
            ..Default::default()
        };
        let out = process_file(&dec, &dec_keys, &d2.input.join("report.csv.pgp")).unwrap();
        assert_eq!(fs::read(&out.output).unwrap(), plaintext);
        assert!(out.signature.unwrap().starts_with("signed by"));

        // Same file, but the configured sender is someone else: refused, nothing published.
        let d3 = dirs();
        fs::copy(&done.output, d3.input.join("report.csv.pgp")).unwrap();
        let stranger = crypto::generate("Stranger", Algorithm::Curve25519).unwrap();
        let mut dec3 = spec(JobKind::Decrypt, &d3);
        dec3.verify_policy = VerifyPolicy::Require;
        let keys3 = JobKeys {
            decrypt: vec![partner.clone()],
            verifiers: vec![stranger.to_public_key()],
            ..Default::default()
        };
        assert!(process_file(&dec3, &keys3, &d3.input.join("report.csv.pgp")).is_err());
        assert!(output_entries(&d3.output).is_empty());

        // With "warn" it is published, with a warning.
        dec3.verify_policy = VerifyPolicy::Warn;
        let warned = process_file(&dec3, &keys3, &d3.input.join("report.csv.pgp")).unwrap();
        assert!(warned.signature.unwrap().starts_with("WARNING"));
    }

    #[test]
    fn tampered_input_leaves_no_output() {
        let d = dirs();
        let key = crypto::generate("K", Algorithm::Curve25519).unwrap();
        let mut encrypted = Vec::new();
        crypto::encrypt(
            &vec![1u8; 300_000][..],
            &mut encrypted,
            &EncryptOptions {
                recipients: &[key.to_public_key()],
                signer: None,
                container: Container::SeipdV1,
                armor: false,
                file_name: "f",
            },
        )
        .unwrap();
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0x40;
        fs::write(d.input.join("data.bin.pgp"), &encrypted).unwrap();
        let keys = JobKeys {
            decrypt: vec![key],
            ..Default::default()
        };
        let err = process_file(
            &spec(JobKind::Decrypt, &d),
            &keys,
            &d.input.join("data.bin.pgp"),
        )
        .unwrap_err();
        assert!(matches!(&err, ProcessError::Failed(message) if !message.is_empty()));
        assert!(
            output_entries(&d.output).is_empty(),
            "no partial plaintext published"
        );
    }

    #[test]
    fn never_overwrites_existing_output() {
        let d = dirs();
        let key = crypto::generate("K", Algorithm::Curve25519).unwrap();
        fs::write(d.input.join("a.csv"), "new").unwrap();
        fs::write(d.output.join("a.csv.pgp"), "existing").unwrap();
        let keys = JobKeys {
            recipients: vec![key.to_public_key()],
            ..Default::default()
        };
        assert!(process_file(&spec(JobKind::Encrypt, &d), &keys, &d.input.join("a.csv")).is_err());
        assert_eq!(
            fs::read_to_string(d.output.join("a.csv.pgp")).unwrap(),
            "existing"
        );
        assert_eq!(output_entries(&d.output), ["a.csv.pgp"]);
    }

    #[test]
    fn move_into_avoids_collisions() {
        let d = dirs();
        let archive = d.input.join("processed");
        for round in 0..3 {
            let file = d.input.join("a.csv");
            fs::write(&file, format!("{round}")).unwrap();
            move_into(&file, &archive).unwrap();
        }
        assert_eq!(output_entries(&archive), ["a.csv", "a.csv.1", "a.csv.2"]);
    }
}
