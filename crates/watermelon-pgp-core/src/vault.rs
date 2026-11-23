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
    crypto::{self, Algorithm, Cert, SignedPublicKey, SignedSecretKey},
    envelope::MasterKey,
    platform,
    store::{self, Customer, KeyRecord, KeyRow, Store},
};

pub const DB_FILE: &str = "watermelon.db";
pub const MASTER_KEY_FILE: &str = "master.key";
pub const MIN_ADMIN_PASSWORD_LEN: usize = 12;

const SETTING_MASTER_KEY_CHECK: &str = "master_key_check";
const SETTING_ADMIN_PASSWORD: &str = "admin_password";
const MASTER_KEY_CHECK_CONTEXT: &str = "master-key-check";
const MASTER_KEY_CHECK_VALUE: &[u8] = b"watermelon-pgp";

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
        let db_path = data_dir.join(DB_FILE);
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
        platform::create_private_dir(data_dir)?;
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
                "{} (run `watermelon init` first)",
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

    pub fn keys(&self, customer_id: Option<i64>) -> Result<Vec<KeyRecord>> {
        store::keys(self.store.conn(), customer_id)
    }

    pub fn generate_key(
        &self,
        actor: Actor,
        customer_id: i64,
        user_id: &str,
        algorithm: Algorithm,
    ) -> Result<KeyRecord> {
        if user_id.trim().is_empty() {
            return Err(Error::Invalid("user ID must not be empty".into()));
        }
        let cert = Cert::Secret(crypto::generate(user_id.trim(), algorithm)?);
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

    /// Import every key in `data` (armored or binary) for one customer, all or nothing.
    ///
    /// Passphrase-protected secret keys are unlocked with `passphrase` and stored under the
    /// master key instead; the passphrase itself is not kept.
    pub fn import_keys(
        &self,
        actor: Actor,
        customer_id: i64,
        data: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Vec<KeyRecord>> {
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
                if let Some(existing) = store::key_by_fingerprint(tx, &info.fingerprint)? {
                    let adds_secret = info.has_secret && !existing.has_secret;
                    if existing.deleted_at.is_none() && existing.customer_id != customer_id {
                        return Err(Error::Conflict(format!(
                            "key {} already belongs to customer {:?}",
                            info.fingerprint, existing.customer_name
                        )));
                    }
                    if existing.deleted_at.is_none() && !adds_secret {
                        return Err(Error::Conflict(format!(
                            "key {} is already imported",
                            info.fingerprint
                        )));
                    }
                }
                let record = self.save(tx, customer_id, cert)?;
                audit::record(
                    tx,
                    &Entry::new(actor, Action::KeyImport)
                        .customer(customer_id)
                        .key(&record.fingerprint)
                        .detail(format!(
                            "{} {} ({})",
                            record.algorithm,
                            record.label(),
                            if record.has_secret {
                                "secret"
                            } else {
                                "public"
                            }
                        )),
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
                .customer(record.customer_id)
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
                .customer(record.customer_id)
                .key(&record.fingerprint),
            now(),
        )?;
        Ok(armored)
    }

    pub fn delete_key(&self, actor: Actor, fingerprint: &str) -> Result<KeyRecord> {
        let record = self.find_key(fingerprint)?;
        self.store.transaction(|tx| {
            store::soft_delete_key(tx, &record.fingerprint, now())?;
            audit::record(
                tx,
                &Entry::new(actor, Action::KeyDelete)
                    .customer(record.customer_id)
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
        customer_id: i64,
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
