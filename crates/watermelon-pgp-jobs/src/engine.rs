//! Running jobs: one polling pass at a time per job, many jobs in parallel.

use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use watermelon_pgp_core::{
    audit::Action,
    jobs::{self, Job, JobKind},
    vault::Vault,
};

use crate::{
    process::{self, JobKeys, ProcessError},
    scan::Scanner,
};

/// What one polling pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    pub processed: usize,
    pub failed: usize,
    /// A problem with the job itself (unreadable folder, unusable key), not with one file.
    pub error: Option<String>,
    /// Set when the pass paused the job.
    pub paused: Option<String>,
    /// Temp files left in the output folder by an earlier crash, now removed.
    pub removed_temp_files: usize,
}

/// Run one polling pass of a job: scan its input folder and process every settled file.
///
/// The vault lock is only held for database work, never while files are being processed.
pub fn run_pass(vault: &Mutex<Vault>, job_id: i64, scanner: &mut Scanner) -> PassReport {
    let mut report = PassReport::default();
    let prepared = {
        let vault = vault.lock().unwrap();
        prepare(&vault, job_id)
    };
    let (job, keys) = match prepared {
        Ok(Some(prepared)) => prepared,
        Ok(None) => return report,
        Err(Prepare::Pause(reason)) => {
            let _ = vault.lock().unwrap().pause_job(job_id, &reason);
            report.paused = Some(reason);
            return report;
        }
        Err(Prepare::Error(error)) => {
            let _ = vault.lock().unwrap().record_job_run(job_id, Some(&error));
            report.error = Some(error);
            return report;
        }
    };

    match process::remove_stale_temp_files(&job.spec.output_dir, process::STALE_TEMP_AFTER) {
        Ok(removed) => report.removed_temp_files = removed.len(),
        Err(e) => {
            let error = format!(
                "cleaning up temp files in {}: {e}",
                job.spec.output_dir.display()
            );
            let _ = vault.lock().unwrap().record_job_run(job.id, Some(&error));
            report.error = Some(error);
            return report;
        }
    }

    let ready = match scanner.scan(&job.spec.input_dir) {
        Ok(ready) => ready,
        Err(e) => {
            let error = format!("reading {}: {e}", job.spec.input_dir.display());
            let _ = vault.lock().unwrap().record_job_run(job.id, Some(&error));
            report.error = Some(error);
            return report;
        }
    };

    for input in ready {
        let outcome = handle_file(&job, &keys, &input);
        // Processed and failed files are gone from the folder; a busy one must settle again.
        scanner.forget(&input);
        let (action, detail) = match outcome {
            Outcome::Processed(detail) => {
                report.processed += 1;
                (Action::FileProcessed, detail)
            }
            Outcome::Failed(detail) => {
                report.failed += 1;
                (Action::FileFailed, detail)
            }
            Outcome::Busy => continue,
        };
        let vault = vault.lock().unwrap();
        if let Err(e) = vault.record_file(&job, action, &detail) {
            report.error = Some(format!("writing audit log: {e}"));
        }
    }

    let _ = vault
        .lock()
        .unwrap()
        .record_job_run(job.id, report.error.as_deref());
    report
}

enum Prepare {
    /// The job must not run until someone looks at it.
    Pause(String),
    /// This pass can't run; try again next time.
    Error(String),
}

/// Load the job and its key material. `Ok(None)` means the job is not active.
fn prepare(vault: &Vault, job_id: i64) -> Result<Option<(Job, JobKeys)>, Prepare> {
    let job = match vault.job(job_id) {
        Ok(job) if job.is_active() => job,
        Ok(_) => return Ok(None),
        Err(e) => return Err(Prepare::Error(e.to_string())),
    };
    let spec = &job.spec;
    let mut keys = JobKeys::default();
    match spec.kind {
        JobKind::Encrypt => {
            for fingerprint in &spec.recipients {
                let record = vault
                    .find_key(fingerprint)
                    .map_err(|e| Prepare::Pause(e.to_string()))?;
                jobs::usable(&record).map_err(Prepare::Pause)?;
                keys.recipients.push(
                    vault
                        .public_key(fingerprint)
                        .map_err(|e| Prepare::Error(e.to_string()))?,
                );
            }
            if let Some(signer) = &spec.signer {
                let record = vault
                    .find_key(signer)
                    .map_err(|e| Prepare::Pause(e.to_string()))?;
                jobs::usable(&record).map_err(Prepare::Pause)?;
                keys.signer = Some(
                    vault
                        .secret_key(signer)
                        .map_err(|e| Prepare::Error(e.to_string()))?,
                );
            }
        }
        JobKind::Decrypt => {
            for fingerprint in &spec.decrypt_keys {
                keys.decrypt.push(
                    vault
                        .secret_key(fingerprint)
                        .map_err(|e| Prepare::Pause(e.to_string()))?,
                );
            }
            for fingerprint in &spec.verifiers {
                keys.verifiers.push(
                    vault
                        .public_key(fingerprint)
                        .map_err(|e| Prepare::Pause(e.to_string()))?,
                );
            }
        }
    }
    for dir in [Some(&spec.failed_dir), spec.processed_dir.as_ref()]
        .into_iter()
        .flatten()
    {
        fs::create_dir_all(dir)
            .map_err(|e| Prepare::Error(format!("creating {}: {e}", dir.display())))?;
    }
    Ok(Some((job, keys)))
}

/// What happened to one input file.
enum Outcome {
    /// Processed and moved away; the audit detail.
    Processed(String),
    /// Failed, and moved to the failed folder if possible; the audit detail.
    Failed(String),
    /// Windows: another process has it open for writing. Left alone for a later pass, without
    /// an audit entry.
    Busy,
}

/// Process one file and move the source away.
fn handle_file(job: &Job, keys: &JobKeys, input: &Path) -> Outcome {
    let name = input.file_name().unwrap_or_default().to_string_lossy();
    match process::process_file(&job.spec, keys, input) {
        Ok(done) => {
            let mut detail = format!(
                "{name} -> {} ({} bytes, sha256 {})",
                done.output.display(),
                done.bytes,
                done.sha256
            );
            if let Some(signature) = &done.signature {
                detail.push_str(&format!("; {signature}"));
            }
            let disposal = match &job.spec.processed_dir {
                Some(dir) => process::move_into(input, dir).map(|_| ()),
                None => fs::remove_file(input),
            };
            if let Err(e) = disposal {
                // The output is published; leaving the source would encrypt it again next pass.
                detail.push_str(&format!("; WARNING: could not move source away: {e}"));
                return Outcome::Failed(detail);
            }
            Outcome::Processed(detail)
        }
        Err(ProcessError::InUse) => Outcome::Busy,
        Err(ProcessError::Failed(error)) => {
            let sha256 = process::sha256_of(input).unwrap_or_else(|e| format!("unreadable: {e}"));
            let mut detail = format!("{name}: {error} (sha256 {sha256})");
            match process::move_into(input, &job.spec.failed_dir) {
                Ok(moved) => detail.push_str(&format!("; moved to {}", moved.display())),
                Err(e) => {
                    detail.push_str(&format!("; WARNING: could not move to failed folder: {e}"))
                }
            }
            Outcome::Failed(detail)
        }
    }
}

/// Runs every active job on its own schedule until stopped.
pub struct Engine {
    vault: Arc<Mutex<Vault>>,
    workers: usize,
}

impl Engine {
    pub fn new(vault: Arc<Mutex<Vault>>, workers: usize) -> Self {
        Self {
            vault,
            workers: workers.max(1),
        }
    }

    /// Default worker count: the number of CPUs.
    pub fn default_workers() -> usize {
        thread::available_parallelism().map_or(2, |n| n.get())
    }

    /// Run passes until `stop` is set; passes in progress finish before this returns.
    /// `on_pass` sees every pass that did something or reported a problem.
    pub fn run(&self, stop: &AtomicBool, on_pass: impl Fn(&str, &PassReport)) {
        let (task_tx, task_rx) = mpsc::channel::<(i64, Scanner)>();
        let task_rx = Arc::new(Mutex::new(task_rx));
        let (done_tx, done_rx) = mpsc::channel::<(i64, Scanner, PassReport)>();

        let workers: Vec<_> = (0..self.workers)
            .map(|_| {
                let task_rx = Arc::clone(&task_rx);
                let done_tx = done_tx.clone();
                let vault = Arc::clone(&self.vault);
                thread::spawn(move || {
                    loop {
                        let task = task_rx.lock().unwrap().recv();
                        let Ok((job_id, mut scanner)) = task else {
                            break;
                        };
                        let report = run_pass(&vault, job_id, &mut scanner);
                        if done_tx.send((job_id, scanner, report)).is_err() {
                            break;
                        }
                    }
                })
            })
            .collect();
        drop(done_tx);

        let mut states: HashMap<i64, JobState> = HashMap::new();
        let mut names: HashMap<i64, String> = HashMap::new();
        while !stop.load(Ordering::Relaxed) {
            while let Ok((job_id, scanner, report)) = done_rx.try_recv() {
                if let Some(state) = states.get_mut(&job_id) {
                    state.scanner = Some(scanner);
                    state.next_due = Instant::now() + state.interval;
                }
                if report != PassReport::default() {
                    on_pass(names.get(&job_id).map_or("?", String::as_str), &report);
                }
            }

            let jobs = match self.vault.lock().unwrap().jobs() {
                Ok(jobs) => jobs,
                Err(e) => {
                    on_pass(
                        "(scheduler)",
                        &PassReport {
                            error: Some(format!("loading jobs: {e}")),
                            ..Default::default()
                        },
                    );
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            let active: HashMap<i64, Job> = jobs
                .into_iter()
                .filter(Job::is_active)
                .map(|job| (job.id, job))
                .collect();
            // Forget idle jobs that were disabled or deleted; running ones are dropped when done.
            states.retain(|id, state| active.contains_key(id) || state.scanner.is_none());

            for (id, job) in &active {
                names.insert(*id, format!("{}/{}", job.customer_name, job.spec.name));
                let state = states.entry(*id).or_insert_with(|| JobState::new(job));
                if state.updated_at != job.updated_at {
                    // Edited, or re-enabled: start over so stale observations don't count.
                    *state = JobState::new(job);
                }
                if state.next_due <= Instant::now()
                    && let Some(scanner) = state.scanner.take()
                {
                    let _ = task_tx.send((*id, scanner));
                }
            }
            thread::sleep(Duration::from_millis(250));
        }

        drop(task_tx);
        for worker in workers {
            let _ = worker.join();
        }
    }
}

struct JobState {
    /// `None` while a pass is running.
    scanner: Option<Scanner>,
    next_due: Instant,
    interval: Duration,
    updated_at: i64,
}

impl JobState {
    fn new(job: &Job) -> Self {
        Self {
            scanner: Some(Scanner::default()),
            next_due: Instant::now(),
            interval: Duration::from_secs(job.spec.poll_interval_secs.into()),
            updated_at: job.updated_at,
        }
    }
}
