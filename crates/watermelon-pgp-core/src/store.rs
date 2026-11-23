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

/// A stored key, without its secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub id: i64,
    pub customer_id: i64,
    pub customer_name: String,
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
    pub customer_id: i64,
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
        for (version, sql) in MIGRATIONS.iter().enumerate().skip(applied) {
            let tx = self.conn.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", version as i64 + 1)?;
            tx.commit()?;
        }
        Ok(())
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
                "SELECT {KEY_COLUMNS} FROM keys k JOIN customers c ON c.id = k.customer_id
                 WHERE k.fingerprint = ?1"
            ),
            [fingerprint],
            key_from_row,
        )
        .optional()?)
}

/// Active (not deleted) keys, optionally for one customer.
pub fn keys(conn: &Connection, customer_id: Option<i64>) -> Result<Vec<KeyRecord>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {KEY_COLUMNS} FROM keys k JOIN customers c ON c.id = k.customer_id
         WHERE k.deleted_at IS NULL AND (?1 IS NULL OR k.customer_id = ?1)
         ORDER BY c.name, k.user_ids"
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
    Ok(KeyRecord {
        id: row.get(0)?,
        customer_id: row.get(1)?,
        customer_name: row.get(2)?,
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
