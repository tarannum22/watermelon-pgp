//! Job definitions: what a folder job does, which keys it uses, and its run state.
//! Running jobs is the `watermelon-pgp-jobs` crate's business; this module only stores them.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::{
    Error, Result,
    audit::{self, Action, Actor, Entry},
    crypto::Container,
    store::KeyRecord,
    vault::{Vault, now},
};

/// Smallest allowed polling interval, so a misconfiguration cannot spin the disk.
pub const MIN_POLL_INTERVAL_SECS: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Encrypt,
    Decrypt,
}

/// What a decrypt job does with the sender's signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyPolicy {
    /// Signatures are not checked.
    #[default]
    Ignore,
    /// Unsigned or unverifiable files are processed, with a warning in the audit log.
    Warn,
    /// Unsigned or unverifiable files fail.
    Require,
}

/// Everything that defines a job; used to create one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSpec {
    pub name: String,
    pub kind: JobKind,
    pub input_dir: PathBuf,
    pub output_dir: PathBuf,
    /// Where processed source files are moved. `None` deletes them instead.
    pub processed_dir: Option<PathBuf>,
    pub failed_dir: PathBuf,
    pub poll_interval_secs: u32,
    /// Encrypt: recipient certificates.
    pub recipients: Vec<String>,
    /// Encrypt: optional signing key.
    pub signer: Option<String>,
    /// Encrypt: ASCII-armored output.
    pub armor: bool,
    /// Encrypt: output extension, including the dot. Defaults to `.pgp`, or `.asc` when armored.
    pub extension: Option<String>,
    pub container: Container,
    /// Decrypt: secret keys to try.
    pub decrypt_keys: Vec<String>,
    /// Decrypt: certificates whose signatures count as valid.
    pub verifiers: Vec<String>,
    pub verify_policy: VerifyPolicy,
}

impl JobSpec {
    /// A spec with the conventional defaults: `processed/` and `failed/` inside the input
    /// folder, a 30 second polling interval, binary SEIPD v1 output.
    pub fn new(name: &str, kind: JobKind, input_dir: &Path, output_dir: &Path) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            input_dir: input_dir.to_owned(),
            output_dir: output_dir.to_owned(),
            processed_dir: Some(input_dir.join("processed")),
            failed_dir: input_dir.join("failed"),
            poll_interval_secs: 30,
            recipients: Vec::new(),
            signer: None,
            armor: false,
            extension: None,
            container: Container::SeipdV1,
            decrypt_keys: Vec::new(),
            verifiers: Vec::new(),
            verify_policy: VerifyPolicy::Ignore,
        }
    }

    /// The extension an encrypt job appends.
    pub fn output_extension(&self) -> &str {
        match &self.extension {
            Some(ext) => ext,
            None if self.armor => ".asc",
            None => ".pgp",
        }
    }
}

/// A stored job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: i64,
    pub customer_id: i64,
    pub customer_name: String,
    pub spec: JobSpec,
    pub enabled: bool,
    /// Set when the job stopped itself, e.g. because a recipient key expired.
    pub paused_reason: Option<String>,
    pub last_run_at: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Job {
    /// Enabled and not paused.
    pub fn is_active(&self) -> bool {
        self.enabled && self.paused_reason.is_none()
    }
}

impl Vault {
    pub fn create_job(&self, actor: Actor, customer_id: i64, spec: &JobSpec) -> Result<Job> {
        let spec = self.validate_job(spec)?;
        self.store().transaction(|tx| {
            let now = now();
            tx.execute(
                "INSERT INTO jobs (customer_id, name, kind, input_dir, output_dir, processed_dir,
                                   failed_dir, poll_interval_secs, armor, extension, container,
                                   verify_policy, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13, ?13)",
                params![
                    customer_id,
                    spec.name,
                    kind_str(spec.kind),
                    path_str(&spec.input_dir)?,
                    path_str(&spec.output_dir)?,
                    spec.processed_dir.as_deref().map(path_str).transpose()?,
                    path_str(&spec.failed_dir)?,
                    spec.poll_interval_secs,
                    spec.armor,
                    spec.extension,
                    container_str(spec.container),
                    policy_str(spec.verify_policy),
                    now,
                ],
            )
            .map_err(|e| name_conflict(e, &spec.name))?;
            let id = tx.last_insert_rowid();
            insert_job_keys(tx, id, &spec)?;
            audit::record(
                tx,
                &Entry::new(actor, Action::JobCreate)
                    .customer(customer_id)
                    .job(id)
                    .detail(describe(&spec)),
                now,
            )?;
            job_by_id(tx, id)
        })
    }

    /// Replace a job's definition. Its customer and enabled/paused state stay as they are, and
    /// the engine starts the job afresh with the new settings.
    pub fn update_job(&self, actor: Actor, id: i64, spec: &JobSpec) -> Result<Job> {
        let job = self.job(id)?;
        let spec = self.validate_job(spec)?;
        self.store().transaction(|tx| {
            let now = now();
            tx.execute(
                "UPDATE jobs SET name = ?2, kind = ?3, input_dir = ?4, output_dir = ?5,
                    processed_dir = ?6, failed_dir = ?7, poll_interval_secs = ?8, armor = ?9,
                    extension = ?10, container = ?11, verify_policy = ?12, updated_at = ?13
                 WHERE id = ?1",
                params![
                    id,
                    spec.name,
                    kind_str(spec.kind),
                    path_str(&spec.input_dir)?,
                    path_str(&spec.output_dir)?,
                    spec.processed_dir.as_deref().map(path_str).transpose()?,
                    path_str(&spec.failed_dir)?,
                    spec.poll_interval_secs,
                    spec.armor,
                    spec.extension,
                    container_str(spec.container),
                    policy_str(spec.verify_policy),
                    now,
                ],
            )
            .map_err(|e| name_conflict(e, &spec.name))?;
            tx.execute("DELETE FROM job_keys WHERE job_id = ?1", [id])?;
            insert_job_keys(tx, id, &spec)?;
            audit::record(
                tx,
                &Entry::new(actor, Action::JobUpdate)
                    .customer(job.customer_id)
                    .job(id)
                    .detail(describe(&spec)),
                now,
            )?;
            job_by_id(tx, id)
        })
    }

    pub fn jobs(&self) -> Result<Vec<Job>> {
        let mut stmt = self.store().conn().prepare(&format!(
            "SELECT {JOB_COLUMNS} FROM jobs j JOIN customers c ON c.id = j.customer_id
             WHERE j.deleted_at IS NULL ORDER BY c.name, j.name"
        ))?;
        let rows: Vec<Job> = stmt
            .query_map([], job_from_row)?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter()
            .map(|job| with_keys(self.store().conn(), job))
            .collect()
    }

    pub fn job(&self, id: i64) -> Result<Job> {
        job_by_id(self.store().conn(), id)
    }

    /// Find a job by numeric ID or by name (names must then be unique across customers).
    pub fn find_job(&self, query: &str) -> Result<Job> {
        if let Ok(id) = query.parse::<i64>() {
            return self.job(id);
        }
        let mut matches: Vec<_> = self
            .jobs()?
            .into_iter()
            .filter(|job| job.spec.name.eq_ignore_ascii_case(query))
            .collect();
        match matches.len() {
            0 => Err(Error::NotFound(format!("job {query:?}"))),
            1 => Ok(matches.remove(0)),
            _ => Err(Error::Invalid(format!(
                "several customers have a job named {query:?}; use its ID"
            ))),
        }
    }

    /// Enable a job, clearing any pause.
    pub fn enable_job(&self, actor: Actor, id: i64) -> Result<Job> {
        let job = self.job(id)?;
        // Re-check the keys: a job paused for an expired key should not resume silently.
        self.validate_job(&job.spec)?;
        self.set_job_state(actor, &job, Action::JobEnable, true, None)
    }

    pub fn disable_job(&self, actor: Actor, id: i64) -> Result<Job> {
        let job = self.job(id)?;
        self.set_job_state(
            actor,
            &job,
            Action::JobDisable,
            false,
            job.paused_reason.as_deref(),
        )
    }

    /// Stop a job because it cannot run safely; it stays paused until re-enabled.
    pub fn pause_job(&self, id: i64, reason: &str) -> Result<Job> {
        let job = self.job(id)?;
        self.set_job_state(
            Actor::System,
            &job,
            Action::JobPause,
            job.enabled,
            Some(reason),
        )
    }

    pub fn delete_job(&self, actor: Actor, id: i64) -> Result<Job> {
        let job = self.job(id)?;
        self.store().transaction(|tx| {
            tx.execute(
                "UPDATE jobs SET deleted_at = ?2, enabled = 0 WHERE id = ?1",
                params![id, now()],
            )?;
            tx.execute("DELETE FROM job_keys WHERE job_id = ?1", [id])?;
            audit::record(
                tx,
                &Entry::new(actor, Action::JobDelete)
                    .customer(job.customer_id)
                    .job(id)
                    .detail(&job.spec.name),
                now(),
            )
        })?;
        Ok(job)
    }

    /// Record the outcome of one polling pass.
    pub fn record_job_run(&self, id: i64, error: Option<&str>) -> Result<()> {
        self.store().conn().execute(
            "UPDATE jobs SET last_run_at = ?2, last_error = ?3 WHERE id = ?1",
            params![id, now(), error],
        )?;
        Ok(())
    }

    /// Audit one processed or failed file.
    pub fn record_file(&self, job: &Job, action: Action, detail: &str) -> Result<()> {
        audit::record(
            self.store().conn(),
            &Entry::new(Actor::System, action)
                .customer(job.customer_id)
                .job(job.id)
                .detail(detail),
            now(),
        )
    }

    /// Audit that a failed file was moved back into the input folder for another attempt.
    pub fn record_retry(&self, actor: Actor, job: &Job, file_name: &str) -> Result<()> {
        audit::record(
            self.store().conn(),
            &Entry::new(actor, Action::FileRetry)
                .customer(job.customer_id)
                .job(job.id)
                .detail(file_name),
            now(),
        )
    }

    /// Names of active jobs that use the key, so it can't be deleted from under them.
    pub fn jobs_using_key(&self, fingerprint: &str) -> Result<Vec<String>> {
        let mut stmt = self.store().conn().prepare(
            "SELECT DISTINCT j.name FROM job_keys k JOIN jobs j ON j.id = k.job_id
             WHERE k.fingerprint = ?1 AND j.deleted_at IS NULL ORDER BY j.name",
        )?;
        let names = stmt.query_map([fingerprint], |row| row.get(0))?;
        Ok(names.collect::<rusqlite::Result<_>>()?)
    }

    /// Check a spec and resolve its key references to full fingerprints.
    fn validate_job(&self, spec: &JobSpec) -> Result<JobSpec> {
        let mut spec = spec.clone();
        spec.name = spec.name.trim().to_owned();
        if spec.name.is_empty() {
            return Err(Error::Invalid("job name must not be empty".into()));
        }
        if spec.poll_interval_secs < MIN_POLL_INTERVAL_SECS {
            return Err(Error::Invalid(format!(
                "polling interval must be at least {MIN_POLL_INTERVAL_SECS} seconds"
            )));
        }
        validate_dirs(&spec)?;

        match spec.kind {
            JobKind::Encrypt => {
                if spec.recipients.is_empty() {
                    return Err(Error::Invalid(
                        "an encrypt job needs at least one recipient".into(),
                    ));
                }
                if !spec.decrypt_keys.is_empty() || !spec.verifiers.is_empty() {
                    return Err(Error::Invalid(
                        "decrypt and verify keys only apply to decrypt jobs".into(),
                    ));
                }
                if let Some(ext) = &spec.extension
                    && (!ext.starts_with('.') || ext.len() < 2 || ext.contains(['/', '\\']))
                {
                    return Err(Error::Invalid(format!("invalid extension {ext:?}")));
                }
                spec.recipients = self.resolve_keys(&spec.recipients, |key| {
                    usable(key)?;
                    key.can_encrypt
                        .then_some(())
                        .ok_or_else(|| format!("key {} cannot encrypt", key.fingerprint))
                })?;
                if let Some(signer) = &spec.signer {
                    spec.signer = Some(self.resolve_key(signer, needs_secret_signing)?);
                }
            }
            JobKind::Decrypt => {
                if spec.decrypt_keys.is_empty() {
                    return Err(Error::Invalid(
                        "a decrypt job needs at least one decryption key".into(),
                    ));
                }
                if !spec.recipients.is_empty() || spec.signer.is_some() {
                    return Err(Error::Invalid(
                        "recipients and signing keys only apply to encrypt jobs".into(),
                    ));
                }
                if spec.verify_policy != VerifyPolicy::Ignore && spec.verifiers.is_empty() {
                    return Err(Error::Invalid(
                        "verifying signatures needs at least one sender key".into(),
                    ));
                }
                spec.decrypt_keys = self.resolve_keys(&spec.decrypt_keys, |key| {
                    key.has_secret
                        .then_some(())
                        .ok_or_else(|| format!("key {} has no secret key", key.fingerprint))
                })?;
                spec.verifiers = self.resolve_keys(&spec.verifiers, |key| {
                    (!key.revoked)
                        .then_some(())
                        .ok_or_else(|| format!("key {} is revoked", key.fingerprint))
                })?;
            }
        }
        Ok(spec)
    }

    fn resolve_keys(
        &self,
        queries: &[String],
        check: impl Fn(&KeyRecord) -> std::result::Result<(), String>,
    ) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for query in queries {
            let fingerprint = self.resolve_key(query, &check)?;
            if !out.contains(&fingerprint) {
                out.push(fingerprint);
            }
        }
        Ok(out)
    }

    fn resolve_key(
        &self,
        query: &str,
        check: impl Fn(&KeyRecord) -> std::result::Result<(), String>,
    ) -> Result<String> {
        let key = self.find_key(query)?;
        check(&key).map_err(Error::Invalid)?;
        Ok(key.fingerprint)
    }

    fn set_job_state(
        &self,
        actor: Actor,
        job: &Job,
        action: Action,
        enabled: bool,
        paused_reason: Option<&str>,
    ) -> Result<Job> {
        self.store().transaction(|tx| {
            tx.execute(
                "UPDATE jobs SET enabled = ?2, paused_reason = ?3, updated_at = ?4 WHERE id = ?1",
                params![job.id, enabled, paused_reason, now()],
            )?;
            audit::record(
                tx,
                &Entry::new(actor, action)
                    .customer(job.customer_id)
                    .job(job.id)
                    .detail(paused_reason.unwrap_or(&job.spec.name)),
                now(),
            )?;
            job_by_id(tx, job.id)
        })
    }
}

/// Why a key can't be used for encryption right now, if it can't.
pub fn usable(key: &KeyRecord) -> std::result::Result<(), String> {
    if key.revoked {
        return Err(format!("key {} is revoked", key.fingerprint));
    }
    if key.expires_at.is_some_and(|at| at <= now()) {
        return Err(format!("key {} has expired", key.fingerprint));
    }
    Ok(())
}

fn needs_secret_signing(key: &KeyRecord) -> std::result::Result<(), String> {
    usable(key)?;
    if !key.has_secret || !key.can_sign {
        return Err(format!("key {} cannot sign", key.fingerprint));
    }
    Ok(())
}

fn validate_dirs(spec: &JobSpec) -> Result<()> {
    let mut dirs = vec![
        ("input", &spec.input_dir),
        ("output", &spec.output_dir),
        ("failed", &spec.failed_dir),
    ];
    if let Some(processed) = &spec.processed_dir {
        dirs.push(("processed", processed));
    }
    for (label, dir) in &dirs {
        if !dir.is_absolute() {
            return Err(Error::Invalid(format!(
                "{label} folder must be an absolute path: {}",
                dir.display()
            )));
        }
    }
    for (label, dir) in [("input", &spec.input_dir), ("output", &spec.output_dir)] {
        if !dir.is_dir() {
            return Err(Error::Invalid(format!(
                "{label} folder {} does not exist",
                dir.display()
            )));
        }
    }
    for (i, (a_label, a)) in dirs.iter().enumerate() {
        for (b_label, b) in &dirs[i + 1..] {
            if a == b {
                return Err(Error::Invalid(format!(
                    "the {a_label} and {b_label} folders must differ"
                )));
            }
        }
    }
    Ok(())
}

fn describe(spec: &JobSpec) -> String {
    let keys = match spec.kind {
        JobKind::Encrypt => format!("to {}", spec.recipients.join(", ")),
        JobKind::Decrypt => format!("with {}", spec.decrypt_keys.join(", ")),
    };
    format!(
        "{} {:?}: {} -> {} {keys}",
        kind_str(spec.kind),
        spec.name,
        spec.input_dir.display(),
        spec.output_dir.display()
    )
}

const JOB_COLUMNS: &str = "j.id, j.customer_id, c.name, j.name, j.kind, j.input_dir,
    j.output_dir, j.processed_dir, j.failed_dir, j.poll_interval_secs, j.armor, j.extension,
    j.container, j.verify_policy, j.enabled, j.paused_reason, j.last_run_at, j.last_error,
    j.created_at, j.updated_at";

fn job_by_id(conn: &Connection, id: i64) -> Result<Job> {
    let job = conn
        .query_row(
            &format!(
                "SELECT {JOB_COLUMNS} FROM jobs j JOIN customers c ON c.id = j.customer_id
                 WHERE j.id = ?1 AND j.deleted_at IS NULL"
            ),
            [id],
            job_from_row,
        )
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("job {id}")))?;
    with_keys(conn, job)
}

fn with_keys(conn: &Connection, mut job: Job) -> Result<Job> {
    let mut stmt =
        conn.prepare("SELECT fingerprint, role FROM job_keys WHERE job_id = ?1 ORDER BY rowid")?;
    let rows = stmt.query_map([job.id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (fingerprint, role) = row?;
        match role.as_str() {
            "recipient" => job.spec.recipients.push(fingerprint),
            "sign" => job.spec.signer = Some(fingerprint),
            "decrypt" => job.spec.decrypt_keys.push(fingerprint),
            "verify" => job.spec.verifiers.push(fingerprint),
            _ => {}
        }
    }
    Ok(job)
}

fn job_from_row(row: &Row<'_>) -> rusqlite::Result<Job> {
    let text = |i: usize| row.get::<_, String>(i);
    let bad = |i: usize, what: &str| {
        rusqlite::Error::FromSqlConversionFailure(
            i,
            rusqlite::types::Type::Text,
            format!("unknown {what}").into(),
        )
    };
    let kind = match text(4)?.as_str() {
        "encrypt" => JobKind::Encrypt,
        "decrypt" => JobKind::Decrypt,
        _ => return Err(bad(4, "job kind")),
    };
    let container = match text(12)?.as_str() {
        "seipd-v1" => Container::SeipdV1,
        "seipd-v2" => Container::SeipdV2,
        _ => return Err(bad(12, "container")),
    };
    let verify_policy = match text(13)?.as_str() {
        "ignore" => VerifyPolicy::Ignore,
        "warn" => VerifyPolicy::Warn,
        "require" => VerifyPolicy::Require,
        _ => return Err(bad(13, "verify policy")),
    };
    Ok(Job {
        id: row.get(0)?,
        customer_id: row.get(1)?,
        customer_name: row.get(2)?,
        spec: JobSpec {
            name: row.get(3)?,
            kind,
            input_dir: PathBuf::from(text(5)?),
            output_dir: PathBuf::from(text(6)?),
            processed_dir: row.get::<_, Option<String>>(7)?.map(PathBuf::from),
            failed_dir: PathBuf::from(text(8)?),
            poll_interval_secs: row.get(9)?,
            recipients: Vec::new(),
            signer: None,
            armor: row.get(10)?,
            extension: row.get(11)?,
            container,
            decrypt_keys: Vec::new(),
            verifiers: Vec::new(),
            verify_policy,
        },
        enabled: row.get(14)?,
        paused_reason: row.get(15)?,
        last_run_at: row.get(16)?,
        last_error: row.get(17)?,
        created_at: row.get(18)?,
        updated_at: row.get(19)?,
    })
}

fn insert_job_keys(conn: &Connection, job_id: i64, spec: &JobSpec) -> Result<()> {
    let roles = [
        ("recipient", &spec.recipients),
        ("decrypt", &spec.decrypt_keys),
        ("verify", &spec.verifiers),
    ];
    for (role, fingerprints) in roles {
        for fingerprint in fingerprints {
            insert_job_key(conn, job_id, fingerprint, role)?;
        }
    }
    if let Some(signer) = &spec.signer {
        insert_job_key(conn, job_id, signer, "sign")?;
    }
    Ok(())
}

fn name_conflict(e: rusqlite::Error, name: &str) -> Error {
    match e {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Error::Conflict(format!("this customer already has a job named {name:?}"))
        }
        e => e.into(),
    }
}

fn insert_job_key(conn: &Connection, job_id: i64, fingerprint: &str, role: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO job_keys (job_id, fingerprint, role) VALUES (?1, ?2, ?3)",
        params![job_id, fingerprint, role],
    )?;
    Ok(())
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::Invalid(format!("path is not valid UTF-8: {}", path.display())))
}

fn kind_str(kind: JobKind) -> &'static str {
    match kind {
        JobKind::Encrypt => "encrypt",
        JobKind::Decrypt => "decrypt",
    }
}

fn container_str(container: Container) -> &'static str {
    match container {
        Container::SeipdV1 => "seipd-v1",
        Container::SeipdV2 => "seipd-v2",
    }
}

fn policy_str(policy: VerifyPolicy) -> &'static str {
    match policy {
        VerifyPolicy::Ignore => "ignore",
        VerifyPolicy::Warn => "warn",
        VerifyPolicy::Require => "require",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::Algorithm, envelope::MasterKey, vault};

    struct Fixture {
        dir: tempfile::TempDir,
        vault: Vault,
        customer: i64,
        key: String,
        public_only: String,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(vault::MASTER_KEY_FILE);
        let report = Vault::init(dir.path(), &key_path, "a long admin password").unwrap();
        let vault = Vault::open(&report.db_path, MasterKey::load(&key_path).unwrap()).unwrap();
        let customer = vault.create_customer(Actor::Cli, "ACME").unwrap().id;
        let key = vault
            .generate_key(Actor::Cli, customer, "Ours", Algorithm::Curve25519)
            .unwrap()
            .fingerprint;
        let partner = crate::crypto::generate("Partner", Algorithm::Curve25519).unwrap();
        let armored = crate::crypto::armor_public(&partner.to_public_key()).unwrap();
        let public_only = vault
            .import_keys(Actor::Cli, customer, armored.as_bytes(), None)
            .unwrap()
            .remove(0)
            .fingerprint;
        for sub in ["in", "out"] {
            std::fs::create_dir(dir.path().join(sub)).unwrap();
        }
        Fixture {
            dir,
            vault,
            customer,
            key,
            public_only,
        }
    }

    fn encrypt_spec(f: &Fixture) -> JobSpec {
        let mut spec = JobSpec::new(
            "outbound",
            JobKind::Encrypt,
            &f.dir.path().join("in"),
            &f.dir.path().join("out"),
        );
        spec.recipients = vec![f.public_only[f.public_only.len() - 16..].to_owned()];
        spec
    }

    #[test]
    fn create_and_load_resolves_fingerprints() {
        let f = fixture();
        let mut spec = encrypt_spec(&f);
        spec.signer = Some(f.key.clone());
        spec.armor = true;
        let job = f.vault.create_job(Actor::Cli, f.customer, &spec).unwrap();
        assert_eq!(
            job.spec.recipients,
            vec![f.public_only.clone()],
            "key ID resolved"
        );
        assert_eq!(job.spec.signer.as_deref(), Some(f.key.as_str()));
        assert_eq!(job.spec.output_extension(), ".asc");
        assert!(job.is_active());
        assert_eq!(f.vault.find_job("outbound").unwrap().id, job.id);
        assert_eq!(f.vault.jobs().unwrap(), vec![job.clone()]);
        assert!(
            f.vault.create_job(Actor::Cli, f.customer, &spec).is_err(),
            "duplicate name"
        );
    }

    #[test]
    fn update_replaces_definition_and_keys() {
        let f = fixture();
        let job = f
            .vault
            .create_job(Actor::Cli, f.customer, &encrypt_spec(&f))
            .unwrap();
        let mut spec = job.spec.clone();
        spec.name = "renamed".into();
        spec.recipients = vec![f.key.clone(), f.public_only.clone()];
        spec.poll_interval_secs = 60;
        let updated = f.vault.update_job(Actor::Admin, job.id, &spec).unwrap();
        assert_eq!(updated.spec, spec);
        assert!(updated.updated_at >= job.updated_at);

        spec.recipients.clear();
        assert!(
            f.vault.update_job(Actor::Admin, job.id, &spec).is_err(),
            "still validated"
        );
        let other = f
            .vault
            .create_job(Actor::Cli, f.customer, &encrypt_spec(&f))
            .unwrap();
        let mut clash = other.spec.clone();
        clash.name = "renamed".into();
        assert!(matches!(
            f.vault.update_job(Actor::Admin, other.id, &clash),
            Err(Error::Conflict(_))
        ));
        let audit = f.vault.audit_events(10).unwrap();
        assert!(audit.iter().any(|e| e.action == "job.update"));
    }

    #[test]
    fn rejects_invalid_specs() {
        let f = fixture();
        let base = encrypt_spec(&f);
        let invalid = [
            JobSpec {
                recipients: vec![],
                ..base.clone()
            },
            JobSpec {
                input_dir: "relative".into(),
                ..base.clone()
            },
            JobSpec {
                output_dir: base.input_dir.clone(),
                ..base.clone()
            },
            JobSpec {
                output_dir: f.dir.path().join("missing"),
                ..base.clone()
            },
            JobSpec {
                poll_interval_secs: 1,
                ..base.clone()
            },
            JobSpec {
                signer: Some(f.public_only.clone()),
                ..base.clone()
            },
            JobSpec {
                extension: Some("pgp".into()),
                ..base.clone()
            },
            JobSpec {
                kind: JobKind::Decrypt,
                ..base.clone()
            },
            JobSpec {
                kind: JobKind::Decrypt,
                recipients: vec![],
                decrypt_keys: vec![f.public_only.clone()],
                ..base.clone()
            },
            JobSpec {
                kind: JobKind::Decrypt,
                recipients: vec![],
                decrypt_keys: vec![f.key.clone()],
                verify_policy: VerifyPolicy::Require,
                ..base.clone()
            },
        ];
        for spec in invalid {
            assert!(
                f.vault.create_job(Actor::Cli, f.customer, &spec).is_err(),
                "should reject {spec:?}"
            );
        }
    }

    #[test]
    fn keys_in_use_cannot_be_deleted() {
        let f = fixture();
        let job = f
            .vault
            .create_job(Actor::Cli, f.customer, &encrypt_spec(&f))
            .unwrap();
        assert_eq!(
            f.vault.jobs_using_key(&f.public_only).unwrap(),
            vec!["outbound"]
        );
        let err = f.vault.delete_key(Actor::Cli, &f.public_only).unwrap_err();
        assert!(err.to_string().contains("outbound"), "{err}");
        f.vault.delete_job(Actor::Cli, job.id).unwrap();
        f.vault.delete_key(Actor::Cli, &f.public_only).unwrap();
    }

    #[test]
    fn pause_and_enable() {
        let f = fixture();
        let job = f
            .vault
            .create_job(Actor::Cli, f.customer, &encrypt_spec(&f))
            .unwrap();
        let paused = f.vault.pause_job(job.id, "recipient expired").unwrap();
        assert!(!paused.is_active());
        assert_eq!(paused.paused_reason.as_deref(), Some("recipient expired"));
        assert!(f.vault.enable_job(Actor::Cli, job.id).unwrap().is_active());
        assert!(!f.vault.disable_job(Actor::Cli, job.id).unwrap().is_active());
        let actions: Vec<_> = f
            .vault
            .audit_events(4)
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(
            actions,
            ["job.disable", "job.enable", "job.pause", "job.create"]
        );
    }
}
