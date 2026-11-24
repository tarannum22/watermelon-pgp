//! The append-only audit log. Rows can only be inserted; the schema rejects updates and deletes.

use rusqlite::{Connection, Row, params};

use crate::Result;

/// Who performed an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// The administrator, via the CLI.
    Cli,
    /// The administrator, via the web UI.
    Admin,
    /// The application itself (jobs, startup checks).
    System,
}

impl Actor {
    pub fn as_str(self) -> &'static str {
        match self {
            Actor::Cli => "cli",
            Actor::Admin => "admin",
            Actor::System => "system",
        }
    }
}

/// Audited actions. The string form is what is stored and shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Init,
    AdminPasswordSet,
    AdminLogin,
    AdminLoginFailed,
    AdminLogout,
    CustomerCreate,
    KeyGenerate,
    KeyImport,
    KeyExportPublic,
    KeyExportSecret,
    KeyDelete,
    Backup,
    JobCreate,
    JobUpdate,
    JobEnable,
    JobDisable,
    JobDelete,
    JobPause,
    FileProcessed,
    FileFailed,
    FileRetry,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Init => "system.init",
            Action::AdminPasswordSet => "admin.password_set",
            Action::AdminLogin => "admin.login",
            Action::AdminLoginFailed => "admin.login_failed",
            Action::AdminLogout => "admin.logout",
            Action::CustomerCreate => "customer.create",
            Action::KeyGenerate => "key.generate",
            Action::KeyImport => "key.import",
            Action::KeyExportPublic => "key.export_public",
            Action::KeyExportSecret => "key.export_secret",
            Action::KeyDelete => "key.delete",
            Action::Backup => "system.backup",
            Action::JobCreate => "job.create",
            Action::JobUpdate => "job.update",
            Action::JobEnable => "job.enable",
            Action::JobDisable => "job.disable",
            Action::JobDelete => "job.delete",
            Action::JobPause => "job.pause",
            Action::FileProcessed => "file.processed",
            Action::FileFailed => "file.failed",
            Action::FileRetry => "file.retry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: i64,
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub customer_id: Option<i64>,
    pub key_fingerprint: Option<String>,
    pub job_id: Option<i64>,
    pub detail: String,
}

/// An event about to be recorded.
pub struct Entry<'a> {
    pub actor: Actor,
    pub action: Action,
    pub customer_id: Option<i64>,
    pub key_fingerprint: Option<&'a str>,
    pub job_id: Option<i64>,
    pub detail: String,
}

impl<'a> Entry<'a> {
    pub fn new(actor: Actor, action: Action) -> Self {
        Self {
            actor,
            action,
            customer_id: None,
            key_fingerprint: None,
            job_id: None,
            detail: String::new(),
        }
    }

    pub fn customer(mut self, id: i64) -> Self {
        self.customer_id = Some(id);
        self
    }

    pub fn key(mut self, fingerprint: &'a str) -> Self {
        self.key_fingerprint = Some(fingerprint);
        self
    }

    pub fn job(mut self, id: i64) -> Self {
        self.job_id = Some(id);
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }
}

pub fn record(conn: &Connection, entry: &Entry<'_>, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_events (at, actor, action, customer_id, key_fingerprint, job_id, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            now,
            entry.actor.as_str(),
            entry.action.as_str(),
            entry.customer_id,
            entry.key_fingerprint,
            entry.job_id,
            entry.detail,
        ],
    )?;
    Ok(())
}

/// The most recent events, newest first.
pub fn recent(conn: &Connection, limit: u32) -> Result<Vec<AuditEvent>> {
    query(
        conn,
        &Filter {
            limit,
            ..Filter::default()
        },
    )
}

/// Which events to list. Empty fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// An exact action (`job.create`) or a category prefix ending in a dot (`job.`).
    pub action: Option<String>,
    pub customer_id: Option<i64>,
    pub job_id: Option<i64>,
    pub key_fingerprint: Option<String>,
    /// Only events older than this ID, for paging backwards.
    pub before_id: Option<i64>,
    pub limit: u32,
}

/// Matching events, newest first.
pub fn query(conn: &Connection, filter: &Filter) -> Result<Vec<AuditEvent>> {
    let action_pattern = filter.action.as_ref().map(|action| {
        if action.ends_with('.') {
            format!("{}%", action.replace(['%', '_'], ""))
        } else {
            action.clone()
        }
    });
    let mut stmt = conn.prepare(
        "SELECT id, at, actor, action, customer_id, key_fingerprint, job_id, detail
         FROM audit_events
         WHERE (?1 IS NULL OR action LIKE ?1)
           AND (?2 IS NULL OR customer_id = ?2)
           AND (?3 IS NULL OR job_id = ?3)
           AND (?4 IS NULL OR key_fingerprint = ?4)
           AND (?5 IS NULL OR id < ?5)
         ORDER BY id DESC LIMIT ?6",
    )?;
    let rows = stmt.query_map(
        params![
            action_pattern,
            filter.customer_id,
            filter.job_id,
            filter.key_fingerprint,
            filter.before_id,
            filter.limit,
        ],
        event_from_row,
    )?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// How many events with this action happened at or after `since`.
pub fn count_since(conn: &Connection, action: Action, since: i64) -> Result<u64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM audit_events WHERE action = ?1 AND at >= ?2",
        params![action.as_str(), since],
        |row| row.get(0),
    )?;
    Ok(count.unsigned_abs())
}

fn event_from_row(row: &Row<'_>) -> rusqlite::Result<AuditEvent> {
    Ok(AuditEvent {
        id: row.get(0)?,
        at: row.get(1)?,
        actor: row.get(2)?,
        action: row.get(3)?,
        customer_id: row.get(4)?,
        key_fingerprint: row.get(5)?,
        job_id: row.get(6)?,
        detail: row.get(7)?,
    })
}
