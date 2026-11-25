//! The application's entry point to keys and customers: combines the OpenPGP wrapper, the
//! master-key envelope and the store, and records every change in the audit log within the
//! same transaction as the change itself.

use std::path::{Path, PathBuf};

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};

use crate::{
    Error, Result,
    audit::{self, Action, Actor, Entry},
    crypto::{self, Algorithm, Cert, RevocationReason, SignedPublicKey, SignedSecretKey},
    envelope::MasterKey,
    platform,
    store::{self, Customer, KeyOwner, KeyRecord, KeyRow, Store},
};

const DB_FILE: &str = "watermelonpgp.db";
/// The database's name up to 0.3, when the command was still `watermelon`.
const LEGACY_DB_FILE: &str = "watermelon.db";
/// The files SQLite keeps next to the database, which move with it.
const DB_SIDECARS: [&str; 3] = ["", "-wal", "-shm"];
pub const MASTER_KEY_FILE: &str = "master.key";
pub const MIN_ADMIN_PASSWORD_LEN: usize = 12;

const SETTING_MASTER_KEY_CHECK: &str = "master_key_check";
const SETTING_ADMIN_PASSWORD: &str = "admin_password";
const MASTER_KEY_CHECK_CONTEXT: &str = "master-key-check";
const MASTER_KEY_CHECK_VALUE: &[u8] = b"watermelon-pgp";

/// The database in `data_dir`. A `watermelon.db` left there by 0.3 or earlier is renamed to
/// [`DB_FILE`] first, along with its `-wal` and `-shm` files, so an upgrade keeps its data.
/// Refuses if both names exist rather than pick one.
pub fn db_path(data_dir: &Path) -> Result<PathBuf> {
    let db = data_dir.join(DB_FILE);
    let legacy = data_dir.join(LEGACY_DB_FILE);
    if !legacy.exists() {
        return Ok(db);
    }
    if db.exists() {
        return Err(Error::Conflict(format!(
            "both {} and {} exist: move the one you don't use out of {}",
            db.display(),
            legacy.display(),
            data_dir.display()
        )));
    }
    // The main file last: if a rename fails, the next start finds the legacy database again.
    for suffix in DB_SIDECARS.iter().rev() {
        let from = data_dir.join(format!("{LEGACY_DB_FILE}{suffix}"));
        if from.exists() {
            let to = data_dir.join(format!("{DB_FILE}{suffix}"));
            std::fs::rename(&from, &to).map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("renaming {} to {}: {e}", from.display(), to.display()),
                ))
            })?;
        }
    }
    Ok(db)
}

pub struct Vault {
    store: Store,
    master: MasterKey,
}

/// Where `init` put things.
pub struct InitReport {
    pub db_path: PathBuf,
    pub master_key_path: PathBuf,
}

impl Vault {
    /// Create a new data directory: database, master keyfile and admin password.
    /// Refuses to touch an existing database or keyfile.
    pub fn init(
        data_dir: &Path,
        master_key_path: &Path,
        admin_password: &str,
    ) -> Result<InitReport> {
        check_admin_password(admin_password)?;
        let db_path = db_path(data_dir)?;
        if db_path.exists() {
            return Err(Error::Conflict(format!(
                "{} already exists",
                db_path.display()
            )));
        }
        if master_key_path.exists() {
            return Err(Error::Conflict(format!(
                "{} already exists",
                master_key_path.display()
            )));
        }
        platform::secure_data_dir(data_dir)?;
        if let Some(parent) = master_key_path.parent() {
            platform::create_private_dir(parent)?;
        }

        let master = MasterKey::generate();
        master.write_new(master_key_path)?;
        let store = Store::open(&db_path)?;
        platform::make_private(&db_path)?;
        let vault = Self { store, master };
        let check = vault
            .master
            .seal(MASTER_KEY_CHECK_VALUE, MASTER_KEY_CHECK_CONTEXT);
        let hash = hash_password(admin_password)?;
        vault.store.transaction(|tx| {
            store::set_setting(tx, SETTING_MASTER_KEY_CHECK, &hex::encode(check))?;
            store::set_setting(tx, SETTING_ADMIN_PASSWORD, &hash)?;
            audit::record(tx, &Entry::new(Actor::Cli, Action::Init), now())
        })?;
        Ok(InitReport {
            db_path,
            master_key_path: master_key_path.to_owned(),
        })
    }

    /// Open an initialized database, verifying that `master` is the key it was created with.
    pub fn open(db_path: &Path, master: MasterKey) -> Result<Self> {
        if !db_path.exists() {
            return Err(Error::NotFound(format!(
                "{} (run `watermelonpgp init` first)",
                db_path.display()
            )));
        }
        Self::with_store(Store::open(db_path)?, master)
    }

    fn with_store(store: Store, master: MasterKey) -> Result<Self> {
        let check = store::get_setting(store.conn(), SETTING_MASTER_KEY_CHECK)?
            .ok_or_else(|| Error::Invalid("database was not initialized".into()))?;
        let check = hex::decode(check).map_err(|_| Error::Unseal)?;
        match master.open(&check, MASTER_KEY_CHECK_CONTEXT) {
            Ok(value) if value.as_slice() == MASTER_KEY_CHECK_VALUE => {}
            _ => {
                return Err(Error::MasterKey(
                    "this master key does not belong to this database".into(),
                ));
            }
        }
        Ok(Self { store, master })
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn verify_admin_password(&self, password: &str) -> Result<bool> {
        let Some(hash) = store::get_setting(self.store.conn(), SETTING_ADMIN_PASSWORD)? else {
            return Ok(false);
        };
        Ok(PasswordHash::new(&hash).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        }))
    }

    pub fn set_admin_password(&self, actor: Actor, password: &str) -> Result<()> {
        check_admin_password(password)?;
        let hash = hash_password(password)?;
        self.store.transaction(|tx| {
            store::set_setting(tx, SETTING_ADMIN_PASSWORD, &hash)?;
            audit::record(tx, &Entry::new(actor, Action::AdminPasswordSet), now())
        })
    }

    pub fn create_customer(&self, actor: Actor, name: &str) -> Result<Customer> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid("customer name must not be empty".into()));
        }
        self.store.transaction(|tx| {
            let customer = store::insert_customer(tx, name, now())?;
            audit::record(
                tx,
                &Entry::new(actor, Action::CustomerCreate)
                    .customer(customer.id)
                    .detail(name),
                now(),
            )?;
            Ok(customer)
        })
    }

    pub fn customers(&self) -> Result<Vec<Customer>> {
        store::customers(self.store.conn())
    }

    pub fn customer(&self, name: &str) -> Result<Customer> {
        store::customer_by_name(self.store.conn(), name)
    }

    pub fn customer_by_id(&self, id: i64) -> Result<Customer> {
        store::customer_by_id(self.store.conn(), id)
    }

    pub fn keys(&self, customer_id: Option<i64>) -> Result<Vec<KeyRecord>> {
        store::keys(self.store.conn(), customer_id)
    }

    /// Generate a key pair, for a customer or (with `None`) as an anonymous key.
    pub fn generate_key(
        &self,
        actor: Actor,
        customer_id: impl Into<Option<i64>>,
        user_id: &str,
        algorithm: Algorithm,
    ) -> Result<KeyRecord> {
        if user_id.trim().is_empty() {
            return Err(Error::Invalid("user ID must not be empty".into()));
        }
        let key = crypto::generate(user_id.trim(), algorithm)?;
        self.add_generated_key(actor, customer_id.into(), key)
    }

    /// Store a key made with [`crypto::generate`]. Lets callers generate (slow for RSA) without
    /// holding whatever lock guards the vault.
    pub fn add_generated_key(
        &self,
        actor: Actor,
        customer_id: impl Into<Option<i64>>,
        key: SignedSecretKey,
    ) -> Result<KeyRecord> {
        let customer_id = customer_id.into();
        let cert = Cert::Secret(key);
        self.store.transaction(|tx| {
            let record = self.save(tx, customer_id, &cert)?;
            audit::record(
                tx,
                &Entry::new(actor, Action::KeyGenerate)
                    .customer(customer_id)
                    .key(&record.fingerprint)
                    .detail(format!("{} {}", record.algorithm, record.label())),
                now(),
            )?;
            Ok(record)
        })
    }

    /// Import every key in `data` (armored or binary) for one customer, or as anonymous keys
    /// with `None`, all or nothing.
    ///
    /// Passphrase-protected secret keys are unlocked with `passphrase` and stored under the
    /// master key instead; the passphrase itself is not kept.
    pub fn import_keys(
        &self,
        actor: Actor,
        customer_id: impl Into<Option<i64>>,
        data: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Vec<KeyRecord>> {
        let customer_id = customer_id.into();
        let mut certs = crypto::parse_certs(data)?;
        for cert in &mut certs {
            if cert.is_locked() {
                let fingerprint = cert.info().fingerprint;
                let passphrase = passphrase.ok_or_else(|| {
                    Error::Invalid(format!(
                        "secret key {fingerprint} is passphrase-protected; a passphrase is required"
                    ))
                })?;
                cert.unlock(passphrase).map_err(|_| {
                    Error::Invalid(format!("wrong passphrase for key {fingerprint}"))
                })?;
            }
        }

        self.store.transaction(|tx| {
            let mut imported = Vec::new();
            for cert in &certs {
                let info = cert.info();
                let existing = store::key_by_fingerprint(tx, &info.fingerprint)?
                    .filter(|existing| existing.deleted_at.is_none());
                let (record, action, detail) = match existing {
                    Some(existing) if existing.owner.customer_id() != customer_id => {
                        return Err(Error::Conflict(match &existing.owner {
                            KeyOwner::Customer { name, .. } => format!(
                                "key {} already belongs to customer {name:?}",
                                info.fingerprint
                            ),
                            KeyOwner::Anonymous => format!(
                                "key {} is already imported as an anonymous key",
                                info.fingerprint
                            ),
                        }));
                    }
                    Some(existing) if !(info.has_secret && !existing.has_secret) => {
                        let (record, detail) = self.refresh_public(tx, &existing, cert)?;
                        (record, Action::KeyUpdate, detail)
                    }
                    _ => {
                        let record = self.save(tx, customer_id, cert)?;
                        let kind = if record.has_secret {
                            "secret"
                        } else {
                            "public"
                        };
                        let detail = format!("{} {} ({kind})", record.algorithm, record.label());
                        (record, Action::KeyImport, detail)
                    }
                };
                audit::record(
                    tx,
                    &Entry::new(actor, action)
                        .customer(customer_id)
                        .key(&record.fingerprint)
                        .detail(detail),
                    now(),
                )?;
                imported.push(record);
            }
            Ok(imported)
        })
    }

    pub fn export_public(&self, actor: Actor, fingerprint: &str) -> Result<String> {
        let record = self.find_key(fingerprint)?;
        let cert = self.public_key(&record.fingerprint)?;
        let armored = crypto::armor_public(&cert)?;
        audit::record(
            self.store.conn(),
            &Entry::new(actor, Action::KeyExportPublic)
                .customer(record.owner.customer_id())
                .key(&record.fingerprint),
            now(),
        )?;
        Ok(armored)
    }

    /// Export a secret key protected with a new `passphrase`.
    pub fn export_secret(
        &self,
        actor: Actor,
        fingerprint: &str,
        passphrase: &str,
    ) -> Result<String> {
        let record = self.find_key(fingerprint)?;
        let key = self.secret_key(&record.fingerprint)?;
        let armored = crypto::armor_secret(&key, passphrase)?;
        audit::record(
            self.store.conn(),
            &Entry::new(actor, Action::KeyExportSecret)
                .customer(record.owner.customer_id())
                .key(&record.fingerprint),
            now(),
        )?;
        Ok(armored)
    }

    /// Revoke one of our keys. Jobs encrypting to or signing with it pause; it can still decrypt
    /// files that were encrypted to it before. Partners learn about it from its public key.
    pub fn revoke_key(
        &self,
        actor: Actor,
        fingerprint: &str,
        reason: RevocationReason,
        comment: &str,
    ) -> Result<KeyRecord> {
        let record = self.find_key(fingerprint)?;
        if !record.has_secret {
            return Err(Error::Invalid(format!(
                "key {} is not ours (no secret key): import the revoked public key its owner \
                 publishes instead",
                record.fingerprint
            )));
        }
        if record.revoked {
            return Err(Error::Conflict(format!(
                "key {} is already revoked",
                record.fingerprint
            )));
        }
        let mut key = self.secret_key(&record.fingerprint)?;
        crypto::revoke(&mut key, reason, comment.trim())?;
        self.store.transaction(|tx| {
            let updated = self.save(tx, record.owner.customer_id(), &Cert::Secret(key))?;
            let mut detail = format!("{reason:?}");
            if !comment.trim().is_empty() {
                detail = format!("{detail}: {}", comment.trim());
            }
            audit::record(
                tx,
                &Entry::new(actor, Action::KeyRevoke)
                    .customer(record.owner.customer_id())
                    .key(&record.fingerprint)
                    .detail(detail),
                now(),
            )?;
            Ok(updated)
        })
    }

    /// Update a stored key from a newer copy of it, e.g. one with a later expiry date or a
    /// revocation. Only for keys we hold no secret for; our own keys are managed here.
    fn refresh_public(
        &self,
        conn: &rusqlite::Connection,
        existing: &KeyRecord,
        cert: &Cert,
    ) -> Result<(KeyRecord, String)> {
        if existing.has_secret {
            return Err(Error::Conflict(format!(
                "key {} is already imported",
                existing.fingerprint
            )));
        }
        let stored = crypto::public_from_bytes(&store::public_cert(conn, &existing.fingerprint)?)?;
        let merged = Cert::Public(crypto::merge_public(&stored, cert.public())?);
        if merged.to_bytes()? == Cert::Public(stored).to_bytes()? {
            return Err(Error::Conflict(format!(
                "key {} is already imported and unchanged",
                existing.fingerprint
            )));
        }
        let record = self.save(conn, existing.owner.customer_id(), &merged)?;
        let mut changes = Vec::new();
        if record.revoked && !existing.revoked {
            changes.push("now revoked".to_owned());
        }
        if record.expires_at != existing.expires_at {
            changes.push(format!(
                "expiry {} -> {}",
                date(existing.expires_at),
                date(record.expires_at)
            ));
        }
        if record.user_ids != existing.user_ids {
            changes.push(format!("user IDs: {}", record.user_ids.join(", ")));
        }
        if changes.is_empty() {
            changes.push("signatures updated".into());
        }
        Ok((record, changes.join("; ")))
    }

    pub fn delete_key(&self, actor: Actor, fingerprint: &str) -> Result<KeyRecord> {
        let record = self.find_key(fingerprint)?;
        let jobs = self.jobs_using_key(&record.fingerprint)?;
        if !jobs.is_empty() {
            return Err(Error::Conflict(format!(
                "key {} is used by job(s): {}",
                record.fingerprint,
                jobs.join(", ")
            )));
        }
        self.store.transaction(|tx| {
            store::soft_delete_key(tx, &record.fingerprint, now())?;
            audit::record(
                tx,
                &Entry::new(actor, Action::KeyDelete)
                    .customer(record.owner.customer_id())
                    .key(&record.fingerprint)
                    .detail(record.label()),
                now(),
            )
        })?;
        Ok(record)
    }

    /// Find an active key by full fingerprint or by a unique suffix of at least 8 hex digits
    /// (so key IDs work too). Spaces are ignored and case does not matter.
    pub fn find_key(&self, query: &str) -> Result<KeyRecord> {
        let query: String = query
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .trim_start_matches("0x")
            .to_ascii_uppercase();
        if query.len() < 8 || !query.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Invalid(
                "give a fingerprint or key ID (at least 8 hex digits)".into(),
            ));
        }
        let mut matches: Vec<_> = self
            .keys(None)?
            .into_iter()
            .filter(|key| key.fingerprint.ends_with(&query))
            .collect();
        match matches.len() {
            0 => Err(Error::NotFound(format!("key {query}"))),
            1 => Ok(matches.remove(0)),
            n => Err(Error::Invalid(format!(
                "{query} matches {n} keys; give more of the fingerprint"
            ))),
        }
    }

    pub fn public_key(&self, fingerprint: &str) -> Result<SignedPublicKey> {
        crypto::public_from_bytes(&store::public_cert(self.store.conn(), fingerprint)?)
    }

    /// The unlocked secret key, for use by jobs. Never leaves the process unencrypted.
    pub fn secret_key(&self, fingerprint: &str) -> Result<SignedSecretKey> {
        let sealed = store::sealed_secret(self.store.conn(), fingerprint)?;
        let plain = self.master.open(&sealed, &secret_context(fingerprint))?;
        crypto::secret_from_bytes(&plain)
    }

    pub fn audit_events(&self, limit: u32) -> Result<Vec<audit::AuditEvent>> {
        audit::recent(self.store.conn(), limit)
    }

    pub fn query_audit(&self, filter: &audit::Filter) -> Result<Vec<audit::AuditEvent>> {
        audit::query(self.store.conn(), filter)
    }

    pub fn count_audit(&self, filter: &audit::Filter) -> Result<u64> {
        audit::count(self.store.conn(), filter)
    }

    pub fn count_audit_since(&self, action: Action, since: i64) -> Result<u64> {
        audit::count_since(self.store.conn(), action, since)
    }

    /// Check the admin password and audit the attempt. `client` identifies where it came from.
    pub fn login(&self, password: &str, client: &str) -> Result<bool> {
        let ok = self.verify_admin_password(password)?;
        let action = if ok {
            Action::AdminLogin
        } else {
            Action::AdminLoginFailed
        };
        audit::record(
            self.store.conn(),
            &Entry::new(Actor::Admin, action).detail(client),
            now(),
        )?;
        Ok(ok)
    }

    pub fn record_logout(&self, client: &str) -> Result<()> {
        audit::record(
            self.store.conn(),
            &Entry::new(Actor::Admin, Action::AdminLogout).detail(client),
            now(),
        )
    }

    /// Snapshot the database to `dest`. The master key is deliberately not included.
    pub fn backup(&self, actor: Actor, dest: &Path) -> Result<()> {
        audit::record(
            self.store.conn(),
            &Entry::new(actor, Action::Backup).detail(dest.display().to_string()),
            now(),
        )?;
        self.store.backup_to(dest)
    }

    fn save(
        &self,
        conn: &rusqlite::Connection,
        customer_id: Option<i64>,
        cert: &Cert,
    ) -> Result<KeyRecord> {
        let info = cert.info();
        let public = Cert::Public(cert.public()).to_bytes()?;
        let sealed = match cert {
            Cert::Secret(_) => {
                let plain = zeroize::Zeroizing::new(cert.to_bytes()?);
                Some(self.master.seal(&plain, &secret_context(&info.fingerprint)))
            }
            Cert::Public(_) => None,
        };
        store::upsert_key(
            conn,
            &KeyRow {
                customer_id,
                fingerprint: &info.fingerprint,
                user_ids: &info.user_ids,
                algorithm: &info.algorithm,
                created_at: info.created_at,
                expires_at: info.expires_at,
                revoked: info.revoked,
                can_encrypt: info.can_encrypt,
                can_sign: info.can_sign,
                public_cert: &public,
                sealed_secret: sealed.as_deref(),
            },
            now(),
        )?;
        store::key_by_fingerprint(conn, &info.fingerprint)?
            .ok_or_else(|| Error::NotFound(info.fingerprint))
    }
}

/// `2026-11-24`, or `never`.
fn date(unix: Option<i64>) -> String {
    unix.and_then(|t| time::OffsetDateTime::from_unix_timestamp(t).ok())
        .map_or_else(|| "never".into(), |t| t.date().to_string())
}

fn secret_context(fingerprint: &str) -> String {
    format!("secret-key:{fingerprint}")
}

fn check_admin_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_ADMIN_PASSWORD_LEN {
        return Err(Error::Invalid(format!(
            "the admin password must be at least {MIN_ADMIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| Error::Invalid(format!("hashing password: {e}")))
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "a long admin password";

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(MASTER_KEY_FILE);
        let report = Vault::init(dir.path(), &key_path, PASSWORD).unwrap();
        let vault = Vault::open(&report.db_path, MasterKey::load(&key_path).unwrap()).unwrap();
        (dir, vault)
    }

    #[test]
    fn db_path_adopts_a_database_left_by_watermelon_0_3() {
        let (dir, vault) = vault();
        drop(vault);
        for suffix in ["", "-wal", "-shm"] {
            let new = dir.path().join(format!("watermelonpgp.db{suffix}"));
            if new.exists() {
                std::fs::rename(new, dir.path().join(format!("watermelon.db{suffix}"))).unwrap();
            }
        }
        std::fs::write(dir.path().join("watermelon.db-shm"), b"shm").unwrap();

        let db = db_path(dir.path()).unwrap();

        assert_eq!(db, dir.path().join("watermelonpgp.db"));
        assert!(!dir.path().join("watermelon.db").exists());
        assert!(!dir.path().join("watermelon.db-shm").exists());
        assert_eq!(
            std::fs::read(dir.path().join("watermelonpgp.db-shm")).unwrap(),
            b"shm"
        );
        let vault = Vault::open(
            &db,
            MasterKey::load(&dir.path().join(MASTER_KEY_FILE)).unwrap(),
        );
        assert!(vault.unwrap().verify_admin_password(PASSWORD).unwrap());
    }

    #[test]
    fn db_path_leaves_the_old_database_alone_when_both_exist() {
        let (dir, _vault) = vault();
        std::fs::write(dir.path().join("watermelon.db"), b"old").unwrap();

        assert!(
            db_path(dir.path()).is_err(),
            "two databases: refuse to guess"
        );
        assert_eq!(
            std::fs::read(dir.path().join("watermelon.db")).unwrap(),
            b"old"
        );
    }

    #[test]
    fn db_path_of_a_new_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            db_path(dir.path()).unwrap(),
            dir.path().join("watermelonpgp.db")
        );
        assert!(!dir.path().join("watermelonpgp.db").exists());
    }

    #[test]
    fn init_refuses_to_overwrite_and_checks_master_key() {
        let (dir, vault) = vault();
        let key_path = dir.path().join(MASTER_KEY_FILE);
        assert!(Vault::init(dir.path(), &key_path, PASSWORD).is_err());
        assert!(vault.verify_admin_password(PASSWORD).unwrap());
        assert!(!vault.verify_admin_password("wrong password!!").unwrap());
        assert!(Vault::open(&dir.path().join(DB_FILE), MasterKey::generate()).is_err());
        assert!(Vault::init(&dir.path().join("x"), &dir.path().join("k"), "short").is_err());
    }

    #[test]
    fn generate_export_import_lifecycle() {
        let (_dir, vault) = vault();
        let acme = vault.create_customer(Actor::Cli, "ACME").unwrap();
        let globex = vault.create_customer(Actor::Cli, "Globex").unwrap();
        assert!(
            vault.create_customer(Actor::Cli, "acme").is_err(),
            "names are case-insensitive"
        );

        let key = vault
            .generate_key(
                Actor::Cli,
                acme.id,
                "ACME Ops <ops@acme.example>",
                Algorithm::Curve25519,
            )
            .unwrap();
        assert!(key.has_secret && key.can_encrypt);
        let short_id = &key.fingerprint[key.fingerprint.len() - 16..];
        assert_eq!(vault.find_key(&short_id.to_lowercase()).unwrap().id, key.id);

        // The stored secret unseals and is usable.
        vault.secret_key(&key.fingerprint).unwrap();

        // Re-importing the same key is a conflict; importing it for another customer too.
        let public = vault.export_public(Actor::Cli, &key.fingerprint).unwrap();
        assert!(
            vault
                .import_keys(Actor::Cli, acme.id, public.as_bytes(), None)
                .is_err()
        );
        assert!(
            vault
                .import_keys(Actor::Cli, globex.id, public.as_bytes(), None)
                .is_err()
        );

        // Delete, then re-import the secret export with its passphrase.
        let secret = vault
            .export_secret(Actor::Cli, &key.fingerprint, "export pass")
            .unwrap();
        vault.delete_key(Actor::Cli, &key.fingerprint).unwrap();
        assert!(vault.keys(None).unwrap().is_empty());
        assert!(vault.secret_key(&key.fingerprint).is_err());
        assert!(
            vault
                .import_keys(Actor::Cli, acme.id, secret.as_bytes(), None)
                .is_err()
        );
        assert!(
            vault
                .import_keys(Actor::Cli, acme.id, secret.as_bytes(), Some("nope"))
                .is_err()
        );
        let imported = vault
            .import_keys(Actor::Cli, acme.id, secret.as_bytes(), Some("export pass"))
            .unwrap();
        assert_eq!(imported.len(), 1);
        assert!(imported[0].has_secret);
        vault.secret_key(&key.fingerprint).unwrap();

        let actions: Vec<_> = vault
            .audit_events(100)
            .unwrap()
            .into_iter()
            .rev()
            .map(|e| e.action)
            .collect();
        assert_eq!(
            actions,
            [
                "system.init",
                "customer.create",
                "customer.create",
                "key.generate",
                "key.export_public",
                "key.export_secret",
                "key.delete",
                "key.import",
            ]
        );
    }

    #[test]
    fn public_key_can_be_upgraded_with_its_secret() {
        let (_dir, vault) = vault();
        let acme = vault.create_customer(Actor::Cli, "ACME").unwrap();
        let key = crypto::generate("Partner <p@example.com>", Algorithm::Curve25519).unwrap();
        let public = crypto::armor_public(&key.to_public_key()).unwrap();
        let secret = crypto::armor_secret(&key, "pw").unwrap();
        let first = vault
            .import_keys(Actor::Cli, acme.id, public.as_bytes(), None)
            .unwrap();
        assert!(!first[0].has_secret);
        let second = vault
            .import_keys(Actor::Cli, acme.id, secret.as_bytes(), Some("pw"))
            .unwrap();
        assert!(second[0].has_secret);
        assert_eq!(first[0].id, second[0].id);
    }

    #[test]
    fn anonymous_keys_belong_to_no_customer() {
        // A partner's vault, to import their key from.
        let (_other_dir, other) = vault();
        let (_dir, vault) = vault();
        let acme = vault.create_customer(Actor::Cli, "ACME").unwrap().id;
        vault
            .generate_key(Actor::Cli, acme, "ACME", Algorithm::Curve25519)
            .unwrap();
        let ours = vault
            .generate_key(
                Actor::Admin,
                None,
                "Ours <ops@example.com>",
                Algorithm::Curve25519,
            )
            .unwrap();
        assert_eq!(ours.owner, KeyOwner::Anonymous);
        assert!(ours.has_secret);

        // Listed with all keys (last), not with any customer's.
        let all = vault.keys(None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all.last().unwrap().fingerprint, ours.fingerprint);
        assert!(
            vault
                .keys(Some(acme))
                .unwrap()
                .iter()
                .all(|k| k.owner.customer_id() == Some(acme))
        );
        assert_eq!(
            vault.find_key(&ours.fingerprint).unwrap().owner,
            KeyOwner::Anonymous
        );

        // Audited without a customer.
        let event = &vault.audit_events(1).unwrap()[0];
        assert_eq!(event.action, "key.generate");
        assert_eq!(event.customer_id, None);
        assert_eq!(
            event.key_fingerprint.as_deref(),
            Some(ours.fingerprint.as_str())
        );

        // Imported keys can be anonymous too, and an anonymous key can't be imported again for
        // a customer (or the other way round): a key has one owner.
        let partner = other
            .generate_key(Actor::Cli, None, "Partner", Algorithm::Curve25519)
            .unwrap();
        let armored = other
            .export_public(Actor::Cli, &partner.fingerprint)
            .unwrap();
        let imported = vault
            .import_keys(Actor::Admin, None, armored.as_bytes(), None)
            .unwrap();
        assert_eq!(imported[0].owner, KeyOwner::Anonymous);
        let err = vault
            .import_keys(Actor::Admin, acme, armored.as_bytes(), None)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("already imported as an anonymous key"),
            "{err}"
        );
        let acme_key = vault.keys(Some(acme)).unwrap().remove(0);
        let acme_public = vault
            .export_public(Actor::Cli, &acme_key.fingerprint)
            .unwrap();
        let err = vault
            .import_keys(Actor::Admin, None, acme_public.as_bytes(), None)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("already belongs to customer \"ACME\""),
            "{err}"
        );

        // Usable like any other key: revoke, export, delete.
        vault
            .revoke_key(
                Actor::Admin,
                &ours.fingerprint,
                RevocationReason::Retired,
                "",
            )
            .unwrap();
        assert!(
            vault
                .export_secret(Actor::Admin, &ours.fingerprint, "a new passphrase")
                .is_ok()
        );
        vault.delete_key(Actor::Admin, &ours.fingerprint).unwrap();
    }

    #[test]
    fn revoking_our_key_and_learning_about_a_partners_revocation() {
        let (_dir, ours) = vault();
        let acme = ours.create_customer(Actor::Cli, "ACME").unwrap().id;
        let key = ours
            .generate_key(Actor::Cli, acme, "ACME", Algorithm::Curve25519)
            .unwrap();
        let stale_public = ours.export_public(Actor::Cli, &key.fingerprint).unwrap();

        let revoked = ours
            .revoke_key(
                Actor::Admin,
                &key.fingerprint,
                RevocationReason::Retired,
                "end of contract",
            )
            .unwrap();
        assert!(revoked.revoked && revoked.has_secret);
        assert!(crate::jobs::usable(&revoked).is_err());
        assert!(matches!(
            ours.revoke_key(
                Actor::Admin,
                &key.fingerprint,
                RevocationReason::Retired,
                ""
            ),
            Err(Error::Conflict(_))
        ));
        let event = ours.audit_events(1).unwrap().remove(0);
        assert_eq!(event.action, "key.revoke");
        assert_eq!(event.detail, "Retired: end of contract");
        // The secret key still works for old files.
        ours.secret_key(&key.fingerprint).unwrap();

        // A partner who has our old public key imports the revoked one.
        let (_dir2, partner) = vault();
        let them = partner.create_customer(Actor::Cli, "Supplier").unwrap().id;
        partner
            .import_keys(Actor::Cli, them, stale_public.as_bytes(), None)
            .unwrap();
        assert!(matches!(
            partner.revoke_key(
                Actor::Admin,
                &key.fingerprint,
                RevocationReason::Retired,
                ""
            ),
            Err(Error::Invalid(_))
        ));
        let fresh = ours.export_public(Actor::Cli, &key.fingerprint).unwrap();
        let updated = partner
            .import_keys(Actor::Cli, them, fresh.as_bytes(), None)
            .unwrap()
            .remove(0);
        assert!(updated.revoked);
        let event = partner.audit_events(1).unwrap().remove(0);
        assert_eq!(
            (event.action.as_str(), event.detail.as_str()),
            ("key.update", "now revoked")
        );

        // Importing the stale copy again changes nothing: revocations are never dropped.
        assert!(matches!(
            partner.import_keys(Actor::Cli, them, stale_public.as_bytes(), None),
            Err(Error::Conflict(_))
        ));
        assert!(partner.find_key(&key.fingerprint).unwrap().revoked);
    }

    #[test]
    fn audit_search_by_actor_time_and_text() {
        let (_dir, vault) = vault();
        let acme = vault.create_customer(Actor::Admin, "ACME Corp").unwrap().id;
        vault.create_customer(Actor::Cli, "Globex").unwrap();
        let key = vault
            .generate_key(
                Actor::Cli,
                acme,
                "Exports <exports@acme.example>",
                Algorithm::Curve25519,
            )
            .unwrap();
        assert!(!vault.login("wrong", "203.0.113.9").unwrap());
        vault
            .store
            .conn()
            .execute(
                "INSERT INTO audit_events (at, actor, action, detail) VALUES (1000, 'system', 'file.failed', '100% broken_file.csv')",
                [],
            )
            .unwrap();

        let actions = |filter: audit::Filter| {
            let filter = audit::Filter {
                limit: 100,
                ..filter
            };
            let events: Vec<String> = vault
                .query_audit(&filter)
                .unwrap()
                .into_iter()
                .map(|e| e.action)
                .collect();
            assert_eq!(vault.count_audit(&filter).unwrap(), events.len() as u64);
            events
        };
        let text = |t: &str| audit::Filter {
            text: Some(t.into()),
            ..Default::default()
        };

        assert_eq!(
            actions(audit::Filter {
                actor: Some("admin".into()),
                ..Default::default()
            }),
            ["admin.login_failed", "customer.create"]
        );
        assert_eq!(
            actions(audit::Filter {
                until: Some(2000),
                ..Default::default()
            }),
            ["file.failed"]
        );
        assert!(
            !actions(audit::Filter {
                since: Some(2000),
                ..Default::default()
            })
            .contains(&"file.failed".to_owned())
        );
        // Subject: customer name, key user ID, fingerprint; and the details. Case-insensitive.
        assert_eq!(
            actions(text("acme corp")),
            ["key.generate", "customer.create"]
        );
        assert_eq!(actions(text("EXPORTS@ACME")), ["key.generate"]);
        assert_eq!(actions(text(&key.fingerprint[30..])), ["key.generate"]);
        assert_eq!(actions(text("203.0.113")), ["admin.login_failed"]);
        // Wildcards are literal.
        assert_eq!(actions(text("100%")), ["file.failed"]);
        assert_eq!(actions(text("en_fi")), ["file.failed"]);
        assert_eq!(actions(text("%")), ["file.failed"]);
        // `_` only where there is an underscore, not "any character".
        assert_eq!(actions(text("_")), ["file.failed", "admin.login_failed"]);
        assert!(actions(text("no such thing")).is_empty());
        assert_eq!(
            actions(text("   ")).len(),
            actions(audit::Filter::default()).len()
        );
        // Filters combine.
        assert_eq!(
            actions(audit::Filter {
                text: Some("acme".into()),
                actor: Some("cli".into()),
                ..Default::default()
            }),
            ["key.generate"]
        );
    }

    #[test]
    fn audit_can_be_filtered_and_paged() {
        let (_dir, vault) = vault();
        let acme = vault.create_customer(Actor::Cli, "ACME").unwrap().id;
        vault.create_customer(Actor::Cli, "Globex").unwrap();
        assert!(!vault.login("wrong password", "10.0.0.1").unwrap());
        assert!(vault.login("a long admin password", "10.0.0.1").unwrap());

        let query = |filter: audit::Filter| {
            vault
                .query_audit(&audit::Filter {
                    limit: 100,
                    ..filter
                })
                .unwrap()
                .into_iter()
                .map(|e| e.action)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            query(audit::Filter {
                action: Some("admin.".into()),
                ..Default::default()
            }),
            ["admin.login", "admin.login_failed"]
        );
        assert_eq!(
            query(audit::Filter {
                customer_id: Some(acme),
                ..Default::default()
            }),
            ["customer.create"]
        );
        let newest = vault.audit_events(1).unwrap().remove(0);
        let older = query(audit::Filter {
            before_id: Some(newest.id),
            ..Default::default()
        });
        assert_eq!(
            older.first().map(String::as_str),
            Some("admin.login_failed")
        );
        assert_eq!(
            vault
                .count_audit_since(Action::AdminLoginFailed, 0)
                .unwrap(),
            1
        );
        assert_eq!(vault.customer_by_id(acme).unwrap().name, "ACME");
    }

    #[test]
    fn audit_log_is_append_only() {
        let (_dir, vault) = vault();
        let conn = vault.store().conn();
        assert!(
            conn.execute("UPDATE audit_events SET detail = 'x'", [])
                .is_err()
        );
        assert!(conn.execute("DELETE FROM audit_events", []).is_err());
    }

    #[test]
    fn sealed_secret_is_bound_to_its_row() {
        let (_dir, vault) = vault();
        let acme = vault.create_customer(Actor::Cli, "ACME").unwrap();
        let a = vault
            .generate_key(Actor::Cli, acme.id, "A", Algorithm::Curve25519)
            .unwrap();
        let b = vault
            .generate_key(Actor::Cli, acme.id, "B", Algorithm::Curve25519)
            .unwrap();
        vault
            .store()
            .conn()
            .execute(
                "UPDATE keys SET sealed_secret = (SELECT sealed_secret FROM keys WHERE fingerprint = ?1)
                 WHERE fingerprint = ?2",
                [&a.fingerprint, &b.fingerprint],
            )
            .unwrap();
        assert!(matches!(
            vault.secret_key(&b.fingerprint),
            Err(Error::Unseal)
        ));
    }
}
