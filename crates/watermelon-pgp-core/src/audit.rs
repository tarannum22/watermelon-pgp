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
    CustomerCreate,
    KeyGenerate,
    KeyImport,
    KeyExportPublic,
    KeyExportSecret,
    KeyDelete,
    Backup,
    JobCreate,
    JobEnable,
    JobDisable,
    JobDelete,
    JobPause,
    FileProcessed,
    FileFailed,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Init => "system.init",
            Action::AdminPasswordSet => "admin.password_set",
            Action::CustomerCreate => "customer.create",
            Action::KeyGenerate => "key.generate",
            Action::KeyImport => "key.import",
            Action::KeyExportPublic => "key.export_public",
            Action::KeyExportSecret => "key.export_secret",
            Action::KeyDelete => "key.delete",
            Action::Backup => "system.backup",
            Action::JobCreate => "job.create",
            Action::JobEnable => "job.enable",
            Action::JobDisable => "job.disable",
            Action::JobDelete => "job.delete",
            Action::JobPause => "job.pause",
            Action::FileProcessed => "file.processed",
            Action::FileFailed => "file.failed",
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
    let mut stmt = conn.prepare(
        "SELECT id, at, actor, action, customer_id, key_fingerprint, job_id, detail
         FROM audit_events ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], event_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
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
