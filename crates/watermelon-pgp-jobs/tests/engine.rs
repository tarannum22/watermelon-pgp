//! A job end to end, through the vault: settle, process, archive, fail, pause, audit.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use watermelon_pgp_core::{
    audit::Actor,
    crypto::{self, Algorithm},
    envelope::MasterKey,
    jobs::{JobKind, JobSpec},
    vault::{self, Vault},
};
use watermelon_pgp_jobs::{Engine, PassReport, failed, run_pass, scan::Scanner};

struct Setup {
    root: tempfile::TempDir,
    vault: Mutex<Vault>,
    customer: i64,
    ours: String,
    partner: crypto::SignedSecretKey,
    partner_fpr: String,
}

impl Setup {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let key_path = root.path().join(vault::MASTER_KEY_FILE);
        let report = Vault::init(
            &root.path().join("data"),
            &key_path,
            "a long admin password",
        )
        .unwrap();
        let vault = Vault::open(&report.db_path, MasterKey::load(&key_path).unwrap()).unwrap();
        let customer = vault.create_customer(Actor::Cli, "ACME").unwrap().id;
        let ours = vault
            .generate_key(Actor::Cli, customer, "Ours", Algorithm::Curve25519)
            .unwrap()
            .fingerprint;
        let partner = crypto::generate("Partner", Algorithm::Curve25519).unwrap();
        let armored = crypto::armor_public(&partner.to_public_key()).unwrap();
        let partner_fpr = vault
            .import_keys(Actor::Cli, customer, armored.as_bytes(), None)
            .unwrap()
            .remove(0)
            .fingerprint;
        Self {
            root,
            vault: Mutex::new(vault),
            customer,
            ours,
            partner,
            partner_fpr,
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        let dir = self.root.path().join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn encrypt_job(&self) -> i64 {
        let mut spec = JobSpec::new(
            "outbound",
            JobKind::Encrypt,
            &self.dir("in"),
            &self.dir("out"),
        );
        spec.recipients = vec![self.partner_fpr.clone()];
        spec.signer = Some(self.ours.clone());
        spec.poll_interval_secs = 5;
        self.vault
            .lock()
            .unwrap()
            .create_job(Actor::Cli, self.customer, &spec)
            .unwrap()
            .id
    }

    fn actions(&self) -> Vec<String> {
        self.vault
            .lock()
            .unwrap()
            .audit_events(100)
            .unwrap()
            .into_iter()
            .rev()
            .map(|e| e.action)
            .collect()
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn pass_processes_settled_files_and_archives_sources() {
    let s = Setup::new();
    let job = s.encrypt_job();
    fs::write(s.dir("in").join("a.csv"), "id\n1\n").unwrap();
    fs::write(s.dir("in").join("b.csv.part"), "still uploading").unwrap();

    let mut scanner = Scanner::default();
    assert_eq!(
        run_pass(&s.vault, job, &mut scanner),
        PassReport::default(),
        "first sighting"
    );
    let report = run_pass(&s.vault, job, &mut scanner);
    assert_eq!(report.processed, 1);
    assert_eq!(report.failed, 0);

    assert_eq!(names(&s.dir("out")), ["a.csv.pgp"]);
    assert_eq!(names(&s.dir("in")), ["b.csv.part", "failed", "processed"]);
    assert_eq!(names(&s.dir("in").join("processed")), ["a.csv"]);

    // The partner can decrypt it.
    let mut plain = Vec::new();
    let encrypted = fs::read(s.dir("out").join("a.csv.pgp")).unwrap();
    crypto::decrypt(
        &encrypted[..],
        &mut plain,
        std::slice::from_ref(&s.partner),
        &[],
    )
    .unwrap();
    assert_eq!(plain, b"id\n1\n");

    let audit = s.vault.lock().unwrap().audit_events(1).unwrap().remove(0);
    assert_eq!(audit.action, "file.processed");
    assert_eq!(audit.job_id, Some(job));
    assert!(audit.detail.contains("sha256"), "{}", audit.detail);
}

#[test]
fn failures_go_to_the_failed_folder() {
    let s = Setup::new();
    let mut spec = JobSpec::new("inbound", JobKind::Decrypt, &s.dir("in"), &s.dir("out"));
    spec.decrypt_keys = vec![s.ours.clone()];
    let job = s
        .vault
        .lock()
        .unwrap()
        .create_job(Actor::Cli, s.customer, &spec)
        .unwrap()
        .id;
    fs::write(s.dir("in").join("garbage.pgp"), "not openpgp at all").unwrap();

    let mut scanner = Scanner::default();
    run_pass(&s.vault, job, &mut scanner);
    let report = run_pass(&s.vault, job, &mut scanner);
    assert_eq!(report.failed, 1);
    assert!(names(&s.dir("out")).is_empty());
    assert_eq!(names(&s.dir("in").join("failed")), ["garbage.pgp"]);
    assert_eq!(s.actions().last().unwrap(), "file.failed");

    let stored = s.vault.lock().unwrap().job(job).unwrap();
    let listed = failed::list(&stored).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "garbage.pgp");
    {
        let vault = s.vault.lock().unwrap();
        for bad in ["../garbage.pgp", "", "missing.pgp"] {
            assert!(
                failed::retry(&vault, Actor::Admin, &stored, bad).is_err(),
                "{bad:?}"
            );
        }
        failed::retry(&vault, Actor::Admin, &stored, "garbage.pgp").unwrap();
    }
    assert!(names(&s.dir("in").join("failed")).is_empty());
    assert!(names(&s.dir("in")).contains(&"garbage.pgp".to_owned()));
    assert_eq!(s.actions().last().unwrap(), "file.retry");
}

#[test]
fn expired_recipient_pauses_the_job() {
    let s = Setup::new();
    let job = s.encrypt_job();
    // Simulate the partner key expiring after the job was set up.
    s.vault
        .lock()
        .unwrap()
        .store()
        .conn()
        .execute(
            "UPDATE keys SET expires_at = 1 WHERE fingerprint = ?1",
            [&s.partner_fpr],
        )
        .unwrap();
    fs::write(s.dir("in").join("a.csv"), "x").unwrap();

    let report = run_pass(&s.vault, job, &mut Scanner::default());
    assert!(report.paused.unwrap().contains("expired"));
    let stored = s.vault.lock().unwrap().job(job).unwrap();
    assert!(!stored.is_active());
    assert_eq!(names(&s.dir("in")), ["a.csv"], "nothing touched");
    assert!(
        s.vault.lock().unwrap().enable_job(Actor::Cli, job).is_err(),
        "cannot resume while the key is still expired"
    );
}

#[test]
fn engine_runs_jobs_until_stopped() {
    let s = Setup::new();
    s.encrypt_job();
    fs::write(s.dir("in").join("a.csv"), "x").unwrap();
    let out = s.dir("out");
    let Setup { vault, .. } = s;
    let vault = Arc::new(vault);
    let engine = Engine::new(Arc::clone(&vault), 2);
    let stop = Arc::new(AtomicBool::new(false));

    let stopper = {
        let stop = Arc::clone(&stop);
        let out = out.clone();
        thread::spawn(move || {
            // Two passes, 5 seconds apart, are needed for the file to settle.
            let deadline = Instant::now() + Duration::from_secs(30);
            while names(&out).is_empty() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(100));
            }
            stop.store(true, Ordering::Relaxed);
        })
    };
    engine.run(&stop, |_, _| {});
    stopper.join().unwrap();
    assert_eq!(names(&out), ["a.csv.pgp"]);
}
