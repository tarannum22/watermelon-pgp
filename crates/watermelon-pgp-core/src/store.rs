//! SQLite persistence. Plain data in, plain data out: no OpenPGP or crypto happens here.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use crate::{Error, Result};

/// Schema migrations, applied in order. `PRAGMA user_version` records how many have run.
const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE settings (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE customers (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at INTEGER NOT NULL
);

CREATE TABLE keys (
    id            INTEGER PRIMARY KEY,
    customer_id   INTEGER NOT NULL REFERENCES customers(id),
    fingerprint   TEXT NOT NULL UNIQUE,
    user_ids      TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    revoked       INTEGER NOT NULL,
    can_encrypt   INTEGER NOT NULL,
    can_sign      INTEGER NOT NULL,
    public_cert   BLOB NOT NULL,
    sealed_secret BLOB,
    added_at      INTEGER NOT NULL,
    deleted_at    INTEGER
);
CREATE INDEX keys_customer ON keys(customer_id);

CREATE TABLE audit_events (
    id              INTEGER PRIMARY KEY,
    at              INTEGER NOT NULL,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    customer_id     INTEGER,
    key_fingerprint TEXT,
    detail          TEXT NOT NULL
);
CREATE INDEX audit_events_at ON audit_events(at);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"#,
    r#"
CREATE TABLE jobs (
    id                 INTEGER PRIMARY KEY,
    customer_id        INTEGER NOT NULL REFERENCES customers(id),
    name               TEXT NOT NULL,
    kind               TEXT NOT NULL CHECK (kind IN ('encrypt', 'decrypt')),
    input_dir          TEXT NOT NULL,
    output_dir         TEXT NOT NULL,
    processed_dir      TEXT,
    failed_dir         TEXT NOT NULL,
    poll_interval_secs INTEGER NOT NULL,
    armor              INTEGER NOT NULL,
    extension          TEXT,
    container          TEXT NOT NULL CHECK (container IN ('seipd-v1', 'seipd-v2')),
    verify_policy      TEXT NOT NULL CHECK (verify_policy IN ('ignore', 'warn', 'require')),
    enabled            INTEGER NOT NULL,
    paused_reason      TEXT,
    last_run_at        INTEGER,
    last_error         TEXT,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    deleted_at         INTEGER
);
CREATE UNIQUE INDEX jobs_customer_name ON jobs(customer_id, name) WHERE deleted_at IS NULL;

CREATE TABLE job_keys (
    job_id      INTEGER NOT NULL REFERENCES jobs(id),
    fingerprint TEXT NOT NULL REFERENCES keys(fingerprint),
    role        TEXT NOT NULL CHECK (role IN ('recipient', 'sign', 'decrypt', 'verify')),
    PRIMARY KEY (job_id, fingerprint, role)
);

ALTER TABLE audit_events ADD COLUMN job_id INTEGER;
"#,
    // v3: filtering the audit log by time, subject and action.
    r#"
CREATE INDEX audit_events_customer ON audit_events (customer_id, id);
CREATE INDEX audit_events_job ON audit_events (job_id, id);
CREATE INDEX audit_events_key ON audit_events (key_fingerprint, id);
CREATE INDEX audit_events_action ON audit_events (action, at);
"#,
    // v4: anonymous keys, which belong to no customer. SQLite can't drop a NOT NULL
    // constraint, so the table is rebuilt (with foreign keys off, see `migrate`).
    r#"
CREATE TABLE keys_new (
    id            INTEGER PRIMARY KEY,
    customer_id   INTEGER REFERENCES customers(id),
    fingerprint   TEXT NOT NULL UNIQUE,
    user_ids      TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    revoked       INTEGER NOT NULL,
    can_encrypt   INTEGER NOT NULL,
    can_sign      INTEGER NOT NULL,
    public_cert   BLOB NOT NULL,
    sealed_secret BLOB,
    added_at      INTEGER NOT NULL,
    deleted_at    INTEGER
);
INSERT INTO keys_new (id, customer_id, fingerprint, user_ids, algorithm, created_at, expires_at,
                      revoked, can_encrypt, can_sign, public_cert, sealed_secret, added_at,
                      deleted_at)
    SELECT id, customer_id, fingerprint, user_ids, algorithm, created_at, expires_at, revoked,
           can_encrypt, can_sign, public_cert, sealed_secret, added_at, deleted_at
    FROM keys;
DROP TABLE keys;
ALTER TABLE keys_new RENAME TO keys;
CREATE INDEX keys_customer ON keys(customer_id);
"#,
];

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Customer {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
}

/// Whose key it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOwner {
    Customer {
        id: i64,
        name: String,
    },
    /// An anonymous key, which belongs to no customer.
    Anonymous,
}

impl KeyOwner {
    pub fn customer_id(&self) -> Option<i64> {
        match self {
            KeyOwner::Customer { id, .. } => Some(*id),
            KeyOwner::Anonymous => None,
        }
    }
}

/// A stored key, without its secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub id: i64,
    pub owner: KeyOwner,
    pub fingerprint: String,
    pub user_ids: Vec<String>,
    pub algorithm: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub has_secret: bool,
    pub added_at: i64,
    pub deleted_at: Option<i64>,
}

impl KeyRecord {
    pub fn label(&self) -> &str {
        self.user_ids
            .first()
            .map(String::as_str)
            .unwrap_or("(no user ID)")
    }
}

/// Everything needed to insert or replace a key row.
pub struct KeyRow<'a> {
    pub customer_id: Option<i64>,
    pub fingerprint: &'a str,
    pub user_ids: &'a [String],
    pub algorithm: &'a str,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub public_cert: &'a [u8],
    pub sealed_secret: Option<&'a [u8]>,
}

const KEY_COLUMNS: &str = "k.id, k.customer_id, c.name, k.fingerprint, k.user_ids, k.algorithm,
    k.created_at, k.expires_at, k.revoked, k.can_encrypt, k.can_sign,
    k.sealed_secret IS NOT NULL, k.added_at, k.deleted_at";

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let applied: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        let applied = usize::try_from(applied).unwrap_or(usize::MAX);
        if applied > MIGRATIONS.len() {
            return Err(Error::Invalid(format!(
                "database schema version {applied} is newer than this build supports ({})",
                MIGRATIONS.len()
            )));
        }
        if applied == MIGRATIONS.len() {
            return Ok(());
        }
        // Rebuilding a table other tables refer to needs foreign keys off (they can only be
        // switched outside a transaction); check them all before switching them back on.
        self.conn.pragma_update(None, "foreign_keys", "OFF")?;
        let result = (|| {
            for (version, sql) in MIGRATIONS.iter().enumerate().skip(applied) {
                let tx = self.conn.unchecked_transaction()?;
                tx.execute_batch(sql)?;
                let broken: i64 =
                    tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                        row.get(0)
                    })?;
                if broken > 0 {
                    return Err(Error::Invalid(format!(
                        "schema migration {} would break {broken} references",
                        version + 1
                    )));
                }
                tx.pragma_update(None, "user_version", version as i64 + 1)?;
                tx.commit()?;
            }
            Ok(())
        })();
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        result
    }

    /// Run `f` inside a transaction that commits only if `f` succeeds.
    pub fn transaction<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let tx = self.conn.unchecked_transaction()?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Write a consistent snapshot of the database to `dest`, which must not exist yet.
    pub fn backup_to(&self, dest: &Path) -> Result<()> {
        if dest.exists() {
            return Err(Error::Conflict(format!(
                "{} already exists",
                dest.display()
            )));
        }
        let dest = dest
            .to_str()
            .ok_or_else(|| Error::Invalid("backup path must be valid UTF-8".into()))?;
        self.conn.execute("VACUUM INTO ?1", [dest])?;
        Ok(())
    }
}

pub fn get_setting(conn: &Connection, name: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT value FROM settings WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?)
}

pub fn set_setting(conn: &Connection, name: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO settings (name, value) VALUES (?1, ?2)
         ON CONFLICT(name) DO UPDATE SET value = excluded.value",
        params![name, value],
    )?;
    Ok(())
}

pub fn insert_customer(conn: &Connection, name: &str, now: i64) -> Result<Customer> {
    conn.execute(
        "INSERT INTO customers (name, created_at) VALUES (?1, ?2)",
        params![name, now],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Error::Conflict(format!("customer {name:?} already exists"))
        }
        e => e.into(),
    })?;
    Ok(Customer {
        id: conn.last_insert_rowid(),
        name: name.to_owned(),
        created_at: now,
    })
}

pub fn customers(conn: &Connection) -> Result<Vec<Customer>> {
    let mut stmt = conn.prepare("SELECT id, name, created_at FROM customers ORDER BY name")?;
    let rows = stmt.query_map([], customer_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn customer_by_name(conn: &Connection, name: &str) -> Result<Customer> {
    conn.query_row(
        "SELECT id, name, created_at FROM customers WHERE name = ?1",
        [name],
        customer_from_row,
    )
    .optional()?
    .ok_or_else(|| Error::NotFound(format!("customer {name:?}")))
}

pub fn customer_by_id(conn: &Connection, id: i64) -> Result<Customer> {
    conn.query_row(
        "SELECT id, name, created_at FROM customers WHERE id = ?1",
        [id],
        customer_from_row,
    )
    .optional()?
    .ok_or_else(|| Error::NotFound(format!("customer {id}")))
}

fn customer_from_row(row: &Row<'_>) -> rusqlite::Result<Customer> {
    Ok(Customer {
        id: row.get(0)?,
        name: row.get(1)?,
        created_at: row.get(2)?,
    })
}

/// Insert a key, or replace the row of a soft-deleted key with the same fingerprint.
pub fn upsert_key(conn: &Connection, key: &KeyRow<'_>, now: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO keys (customer_id, fingerprint, user_ids, algorithm, created_at, expires_at,
                           revoked, can_encrypt, can_sign, public_cert, sealed_secret, added_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(fingerprint) DO UPDATE SET
            customer_id = excluded.customer_id, user_ids = excluded.user_ids,
            algorithm = excluded.algorithm, created_at = excluded.created_at,
            expires_at = excluded.expires_at, revoked = excluded.revoked,
            can_encrypt = excluded.can_encrypt, can_sign = excluded.can_sign,
            public_cert = excluded.public_cert, sealed_secret = excluded.sealed_secret,
            added_at = excluded.added_at, deleted_at = NULL",
        params![
            key.customer_id,
            key.fingerprint,
            key.user_ids.join("\n"),
            key.algorithm,
            key.created_at,
            key.expires_at,
            key.revoked,
            key.can_encrypt,
            key.can_sign,
            key.public_cert,
            key.sealed_secret,
            now,
        ],
    )?;
    Ok(conn.query_row(
        "SELECT id FROM keys WHERE fingerprint = ?1",
        [key.fingerprint],
        |row| row.get(0),
    )?)
}

/// Look up a key by fingerprint, including soft-deleted ones.
pub fn key_by_fingerprint(conn: &Connection, fingerprint: &str) -> Result<Option<KeyRecord>> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT {KEY_COLUMNS} FROM keys k LEFT JOIN customers c ON c.id = k.customer_id
                 WHERE k.fingerprint = ?1"
            ),
            [fingerprint],
            key_from_row,
        )
        .optional()?)
}

/// Active (not deleted) keys, optionally for one customer. Anonymous keys come last.
pub fn keys(conn: &Connection, customer_id: Option<i64>) -> Result<Vec<KeyRecord>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {KEY_COLUMNS} FROM keys k LEFT JOIN customers c ON c.id = k.customer_id
         WHERE k.deleted_at IS NULL AND (?1 IS NULL OR k.customer_id = ?1)
         ORDER BY c.name IS NULL, c.name, k.user_ids"
    ))?;
    let rows = stmt.query_map([customer_id], key_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn public_cert(conn: &Connection, fingerprint: &str) -> Result<Vec<u8>> {
    conn.query_row(
        "SELECT public_cert FROM keys WHERE fingerprint = ?1 AND deleted_at IS NULL",
        [fingerprint],
        |row| row.get(0),
    )
    .optional()?
    .ok_or_else(|| Error::NotFound(format!("key {fingerprint}")))
}

pub fn sealed_secret(conn: &Connection, fingerprint: &str) -> Result<Vec<u8>> {
    conn.query_row(
        "SELECT sealed_secret FROM keys WHERE fingerprint = ?1 AND deleted_at IS NULL",
        [fingerprint],
        |row| row.get::<_, Option<Vec<u8>>>(0),
    )
    .optional()?
    .ok_or_else(|| Error::NotFound(format!("key {fingerprint}")))?
    .ok_or_else(|| Error::Invalid(format!("key {fingerprint} has no secret key material")))
}

pub fn soft_delete_key(conn: &Connection, fingerprint: &str, now: i64) -> Result<()> {
    let changed = conn.execute(
        "UPDATE keys SET deleted_at = ?2 WHERE fingerprint = ?1 AND deleted_at IS NULL",
        params![fingerprint, now],
    )?;
    if changed == 0 {
        return Err(Error::NotFound(format!("key {fingerprint}")));
    }
    Ok(())
}

fn key_from_row(row: &Row<'_>) -> rusqlite::Result<KeyRecord> {
    let user_ids: String = row.get(4)?;
    let owner = match (row.get(1)?, row.get(2)?) {
        (Some(id), Some(name)) => KeyOwner::Customer { id, name },
        _ => KeyOwner::Anonymous,
    };
    Ok(KeyRecord {
        id: row.get(0)?,
        owner,
        fingerprint: row.get(3)?,
        user_ids: user_ids
            .split('\n')
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .collect(),
        algorithm: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
        revoked: row.get(8)?,
        can_encrypt: row.get(9)?,
        can_sign: row.get(10)?,
        has_secret: row.get(11)?,
        added_at: row.get(12)?,
        deleted_at: row.get(13)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database as 0.1.0 left it (schema v3), with a key a job uses.
    fn v3_database() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        for sql in &MIGRATIONS[..3] {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 3).unwrap();
        conn.execute_batch(
            "INSERT INTO customers (id, name, created_at) VALUES (1, 'ACME', 0);
             INSERT INTO keys (id, customer_id, fingerprint, user_ids, algorithm, created_at,
                               revoked, can_encrypt, can_sign, public_cert, sealed_secret,
                               added_at)
                 VALUES (7, 1, 'ABCD', 'ACME', 'Ed25519', 0, 0, 1, 1, x'01', x'02', 0);
             INSERT INTO jobs (id, customer_id, name, kind, input_dir, output_dir, failed_dir,
                               poll_interval_secs, armor, container, verify_policy, enabled,
                               created_at, updated_at)
                 VALUES (3, 1, 'daily', 'encrypt', '/in', '/out', '/in/failed', 30, 0,
                         'seipd-v1', 'ignore', 1, 0, 0);
             INSERT INTO job_keys (job_id, fingerprint, role) VALUES (3, 'ABCD', 'recipient');",
        )
        .unwrap();
        conn
    }

    #[test]
    fn upgrading_from_0_1_0_keeps_keys_and_allows_anonymous_ones() {
        let store = Store::init(v3_database()).unwrap();
        let conn = store.conn();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version as usize, MIGRATIONS.len());

        let key = key_by_fingerprint(conn, "ABCD").unwrap().unwrap();
        assert_eq!(key.id, 7);
        assert_eq!(
            key.owner,
            KeyOwner::Customer {
                id: 1,
                name: "ACME".into()
            }
        );
        assert!(key.has_secret);

        // Foreign keys are back on and still hold: the job's key reference, customers.
        let on: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(on, 1);
        assert!(
            conn.execute("INSERT INTO job_keys VALUES (3, 'NOPE', 'recipient')", [])
                .is_err()
        );
        let row = |customer_id, fingerprint| KeyRow {
            customer_id,
            fingerprint,
            user_ids: &[],
            algorithm: "Ed25519",
            created_at: 0,
            expires_at: None,
            revoked: false,
            can_encrypt: true,
            can_sign: true,
            public_cert: &[1],
            sealed_secret: None,
        };
        assert!(upsert_key(conn, &row(Some(99), "BAD"), 0).is_err());

        // A key without a customer.
        upsert_key(conn, &row(None, "EF01"), 0).unwrap();
        let anonymous = key_by_fingerprint(conn, "EF01").unwrap().unwrap();
        assert_eq!(anonymous.owner, KeyOwner::Anonymous);
        assert_eq!(keys(conn, None).unwrap().len(), 2);
        assert_eq!(keys(conn, Some(1)).unwrap().len(), 1);
    }
}
