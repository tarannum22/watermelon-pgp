//! Large files stream through with bounded memory. Kept in its own test binary so the peak
//! memory measurement only sees this test.

use std::{
    fs::{self, File},
    io::{BufWriter, Write},
};

use watermelon_pgp_core::{
    crypto::{self, Algorithm},
    jobs::{JobKind, JobSpec},
};
use watermelon_pgp_jobs::process::{self, JobKeys};

const SIZE: usize = 512 * 1024 * 1024;
/// Generous for buffers and test overhead, far below the file size.
const MAX_PEAK_RSS: u64 = 128 * 1024 * 1024;

#[test]
fn half_gigabyte_roundtrip_streams() {
    let root = tempfile::tempdir().unwrap();
    let [plain_in, encrypted, encrypted_in, plain_out] =
        ["plain-in", "encrypted", "encrypted-in", "plain-out"].map(|name| {
            let dir = root.path().join(name);
            fs::create_dir(&dir).unwrap();
            dir
        });

    // Pseudo-random content so compression can't hide anything.
    let input = plain_in.join("big.bin");
    {
        let mut out = BufWriter::new(File::create(&input).unwrap());
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut chunk = vec![0u8; 1 << 20];
        for _ in 0..SIZE / chunk.len() {
            for word in chunk.as_chunks_mut::<8>().0 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *word = state.to_le_bytes();
            }
            out.write_all(&chunk).unwrap();
        }
    }

    let key = crypto::generate("Big", Algorithm::Curve25519).unwrap();
    let enc_spec = JobSpec::new("enc", JobKind::Encrypt, &plain_in, &encrypted);
    let enc_keys = JobKeys {
        recipients: vec![key.to_public_key()],
        ..Default::default()
    };
    let done = process::process_file(&enc_spec, &enc_keys, &input).unwrap();
    assert_eq!(done.bytes, SIZE as u64);

    let moved = encrypted_in.join("big.bin.pgp");
    fs::rename(&done.output, &moved).unwrap();
    let dec_spec = JobSpec::new("dec", JobKind::Decrypt, &encrypted_in, &plain_out);
    let dec_keys = JobKeys {
        decrypt: vec![key],
        ..Default::default()
    };
    let back = process::process_file(&dec_spec, &dec_keys, &moved).unwrap();
    assert_eq!(back.output, plain_out.join("big.bin"));
    assert_eq!(
        process::sha256_of(&back.output).unwrap(),
        done.sha256,
        "decrypted file matches the original"
    );

    if let Some(peak) = peak_rss() {
        assert!(
            peak < MAX_PEAK_RSS,
            "peak memory {} MiB: files are being buffered instead of streamed",
            peak >> 20
        );
    }
}

/// Peak resident memory of this process, where cheaply available (Linux).
fn peak_rss() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}
