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
    KeyRevoke,
    KeyUpdate,
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
            Action::KeyRevoke => "key.revoke",
            Action::KeyUpdate => "key.update",
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

    /// The customer concerned; `None` (an anonymous key) is allowed.
    pub fn customer(mut self, id: impl Into<Option<i64>>) -> Self {
        self.customer_id = id.into();
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

/// Which events to list. Empty fields match everything; set fields must all match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// An exact action (`job.create`) or a category prefix ending in a dot (`job.`).
    pub action: Option<String>,
    /// `cli`, `admin` or `system`.
    pub actor: Option<String>,
    pub customer_id: Option<i64>,
    pub job_id: Option<i64>,
    pub key_fingerprint: Option<String>,
    /// Only events at or after this time (Unix seconds).
    pub since: Option<i64>,
    /// Only events before this time (Unix seconds).
    pub until: Option<i64>,
    /// Case-insensitive substring of the action, the details, or what the event is about:
    /// customer name, job name, key fingerprint or key user ID.
    pub text: Option<String>,
    /// Only events older than this ID, for paging backwards.
    pub before_id: Option<i64>,
    pub limit: u32,
}

const FILTERED_EVENTS: &str = "
    FROM audit_events e
    LEFT JOIN customers c ON c.id = e.customer_id
    LEFT JOIN jobs j ON j.id = e.job_id
    LEFT JOIN keys k ON k.fingerprint = e.key_fingerprint
    WHERE (?1 IS NULL OR e.action LIKE ?1 ESCAPE '\\')
      AND (?2 IS NULL OR e.actor = ?2)
      AND (?3 IS NULL OR e.customer_id = ?3)
      AND (?4 IS NULL OR e.job_id = ?4)
      AND (?5 IS NULL OR e.key_fingerprint = ?5)
      AND (?6 IS NULL OR e.at >= ?6)
      AND (?7 IS NULL OR e.at < ?7)
      AND (?8 IS NULL OR e.detail LIKE ?8 ESCAPE '\\' OR e.action LIKE ?8 ESCAPE '\\'
           OR c.name LIKE ?8 ESCAPE '\\' OR j.name LIKE ?8 ESCAPE '\\'
           OR e.key_fingerprint LIKE ?8 ESCAPE '\\' OR k.user_ids LIKE ?8 ESCAPE '\\')
      AND (?9 IS NULL OR e.id < ?9)";

/// Escape `LIKE` wildcards so user input matches literally.
fn like_literal(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn filter_params(filter: &Filter) -> [rusqlite::types::Value; 9] {
    use rusqlite::types::Value;
    let text = |v: Option<String>| v.map_or(Value::Null, Value::Text);
    let int = |v: Option<i64>| v.map_or(Value::Null, Value::Integer);
    let action = filter
        .action
        .as_deref()
        .map(|action| match action.strip_suffix('.') {
            Some(category) => format!("{}.%", like_literal(category)),
            None => like_literal(action),
        });
    let search = filter
        .text
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| format!("%{}%", like_literal(t)));
    [
        text(action),
        text(filter.actor.clone()),
        int(filter.customer_id),
        int(filter.job_id),
        text(filter.key_fingerprint.clone()),
        int(filter.since),
        int(filter.until),
        text(search),
        int(filter.before_id),
    ]
}

/// Matching events, newest first, at most `filter.limit`.
pub fn query(conn: &Connection, filter: &Filter) -> Result<Vec<AuditEvent>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT e.id, e.at, e.actor, e.action, e.customer_id, e.key_fingerprint, e.job_id, e.detail
         {FILTERED_EVENTS} ORDER BY e.id DESC LIMIT ?10"
    ))?;
    let mut values = filter_params(filter).to_vec();
    values.push(rusqlite::types::Value::Integer(filter.limit.into()));
    let rows = stmt.query_map(rusqlite::params_from_iter(values), event_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// How many events match, ignoring `limit` and `before_id`.
pub fn count(conn: &Connection, filter: &Filter) -> Result<u64> {
    let filter = Filter {
        before_id: None,
        ..filter.clone()
    };
    let count: i64 = conn.query_row(
        &format!("SELECT COUNT(*) {FILTERED_EVENTS}"),
        rusqlite::params_from_iter(filter_params(&filter)),
        |row| row.get(0),
    )?;
    Ok(count.unsigned_abs())
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
