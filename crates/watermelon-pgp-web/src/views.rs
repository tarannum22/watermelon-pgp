//! Page layout and small rendering helpers shared by the routes.

use axum::http::StatusCode;
use maud::{DOCTYPE, Markup, html};
use watermelon_pgp_core::{audit::AuditEvent, jobs::Job, store::KeyRecord};

use crate::auth::{CSRF_FIELD, Flash};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// htmx settings: no eval, no inline scripts, no copies of pages in localStorage (they may
/// show key material), and swap error responses too so error pages are visible.
const HTMX_CONFIG: &str = r#"{"allowEval":false,"allowScriptTags":false,"includeIndicatorStyles":false,"historyCacheSize":0,"refreshOnHistoryMiss":true,"selfRequestsOnly":true,"responseHandling":[{"code":"204","swap":false},{"code":"...","swap":true}]}"#;

/// How many days ahead an expiring key is flagged.
pub const EXPIRY_WARNING_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Dashboard,
    Customers,
    Keys,
    Jobs,
    Audit,
    Settings,
}

/// What every logged-in page needs besides its content.
pub struct Page<'a> {
    pub title: &'a str,
    pub nav: Nav,
    pub csrf: &'a str,
    pub flash: Option<Flash>,
}

pub fn asset(name: &str) -> String {
    format!("/static/{name}?v={VERSION}")
}

fn head(title: &str) -> Markup {
    html! {
        meta charset="utf-8";
        meta name="viewport" content="width=device-width, initial-scale=1";
        meta name="htmx-config" content=(HTMX_CONFIG);
        title { (title) " · watermelon-pgp" }
        link rel="icon" href=(asset("logo.svg")) type="image/svg+xml";
        link rel="stylesheet" href=(asset("app.css"));
        script src=(asset("htmx.min.js")) defer {}
    }
}

pub fn layout(page: Page<'_>, content: Markup) -> Markup {
    let links = [
        (Nav::Dashboard, "/", "Dashboard"),
        (Nav::Customers, "/customers", "Customers"),
        (Nav::Keys, "/keys", "Keys"),
        (Nav::Jobs, "/jobs", "Jobs"),
        (Nav::Audit, "/audit", "Audit log"),
        (Nav::Settings, "/settings", "Settings"),
    ];
    html! {
        (DOCTYPE)
        html lang="en" {
            head { (head(page.title)) }
            body hx-boost="true" {
                header.top {
                    a.brand href="/" {
                        img src=(asset("logo.svg")) alt="" width="28" height="28";
                        span { "watermelon-pgp" }
                    }
                    nav {
                        @for (nav, href, label) in links {
                            a href=(href) aria-current=[(nav == page.nav).then_some("page")] { (label) }
                        }
                    }
                    form.logout method="post" action="/logout" {
                        (csrf_field(page.csrf))
                        button.link type="submit" { "Log out" }
                    }
                }
                main {
                    @if let Some(flash) = &page.flash {
                        (flash_message(flash))
                    }
                    (content)
                }
                footer { "watermelon-pgp " (VERSION) }
            }
        }
    }
}

/// A page outside the logged-in layout (login, errors).
pub fn bare(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head { (head(title)) }
            body.bare {
                main.narrow {
                    a.brand href="/" {
                        img src=(asset("logo.svg")) alt="" width="40" height="40";
                        span { "watermelon-pgp" }
                    }
                    (content)
                }
            }
        }
    }
}

pub fn error_page(status: StatusCode, message: &str) -> Markup {
    bare(
        status.canonical_reason().unwrap_or("Error"),
        html! {
            h1 { (status.as_u16()) " " (status.canonical_reason().unwrap_or("Error")) }
            p.flash.error { (message) }
            p { a href="/" { "Back to the dashboard" } }
        },
    )
}

pub fn flash_message(flash: &Flash) -> Markup {
    match flash {
        Flash::Success(message) => html! { p.flash.success role="status" { (message) } },
        Flash::Error(message) => html! { p.flash.error role="alert" { (message) } },
    }
}

pub fn csrf_field(csrf: &str) -> Markup {
    html! { input type="hidden" name=(CSRF_FIELD) value=(csrf); }
}

/// A required checkbox guarding destructive actions; works without JavaScript.
pub fn confirm_box(label: &str) -> Markup {
    html! {
        label.confirm {
            input type="checkbox" name="confirm" value="yes" required;
            " " (label)
        }
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn rfc3339(unix: i64) -> Option<String> {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// `2026-11-24 10:22 UTC`, with the exact time as a tooltip.
pub fn timestamp(unix: i64) -> Markup {
    match rfc3339(unix) {
        Some(full) => {
            let short = format!("{} UTC", full[..16].replace('T', " "));
            html! { time datetime=(full) title=(full) { (short) } }
        }
        None => html! { (unix) },
    }
}

pub fn date(unix: i64) -> Markup {
    match rfc3339(unix) {
        Some(full) => html! { time datetime=(full) title=(full) { (full[..10]) } },
        None => html! { (unix) },
    }
}

/// A fingerprint in groups of four, as gpg prints it.
pub fn fingerprint(fpr: &str) -> Markup {
    let grouped: Vec<&str> = fpr
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect();
    html! { code.fpr { (grouped.join(" ")) } }
}

/// The long key ID: the last 16 hex digits.
pub fn key_id(fpr: &str) -> &str {
    &fpr[fpr.len().saturating_sub(16)..]
}

pub fn key_link(key: &KeyRecord) -> Markup {
    html! {
        a href={ "/keys/" (key.fingerprint) } { (key.label()) }
        " " code.muted { (key_id(&key.fingerprint)) }
    }
}

pub enum Tone {
    Good,
    Warn,
    Bad,
    Neutral,
}

pub fn badge(tone: Tone, text: &str) -> Markup {
    let class = match tone {
        Tone::Good => "badge good",
        Tone::Warn => "badge warn",
        Tone::Bad => "badge bad",
        Tone::Neutral => "badge",
    };
    html! { span class=(class) { (text) } }
}

/// Revoked / expired / expiring soon / valid.
pub fn key_status(key: &KeyRecord) -> Markup {
    let now = now();
    match key.expires_at {
        _ if key.revoked => badge(Tone::Bad, "revoked"),
        Some(at) if at <= now => badge(Tone::Bad, "expired"),
        Some(at) if at - now <= EXPIRY_WARNING_DAYS * 86_400 => badge(
            Tone::Warn,
            &format!("expires in {} days", (at - now) / 86_400),
        ),
        _ => badge(Tone::Good, "valid"),
    }
}

/// Whether the key needs the operator's attention soon.
pub fn key_needs_attention(key: &KeyRecord) -> bool {
    key.revoked
        || key
            .expires_at
            .is_some_and(|at| at - now() <= EXPIRY_WARNING_DAYS * 86_400)
}

pub fn key_capabilities(key: &KeyRecord) -> Markup {
    html! {
        @if key.can_encrypt { span.cap title="can encrypt" { "encrypt" } }
        @if key.can_sign { span.cap title="can sign" { "sign" } }
        @if key.has_secret { span.cap.secret title="we hold the secret key" { "secret" } }
    }
}

pub fn job_state(job: &Job) -> Markup {
    match (&job.paused_reason, job.enabled) {
        (Some(reason), _) => html! { span.badge.bad title=(reason) { "paused" } },
        (None, true) if job.last_error.is_some() => badge(Tone::Warn, "error"),
        (None, true) => badge(Tone::Good, "running"),
        (None, false) => badge(Tone::Neutral, "disabled"),
    }
}

pub fn kind_name(job: &Job) -> &'static str {
    match job.spec.kind {
        watermelon_pgp_core::jobs::JobKind::Encrypt => "encrypt",
        watermelon_pgp_core::jobs::JobKind::Decrypt => "decrypt",
    }
}

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Time filter choices: URL value, label, length in seconds.
pub const PERIODS: &[(&str, &str, i64)] = &[
    ("", "Any time", 0),
    ("1h", "Last hour", 3_600),
    ("24h", "Last 24 hours", 86_400),
    ("7d", "Last 7 days", 7 * 86_400),
    ("30d", "Last 30 days", 30 * 86_400),
];

/// Who did it.
pub const ACTORS: &[(&str, &str)] = &[
    ("", "Anyone"),
    ("admin", "Web UI (admin)"),
    ("cli", "Command line"),
    ("system", "System (jobs)"),
];

/// Action filter choices: categories, then the actions worth finding on their own.
pub const ACTIONS: &[(&str, &str)] = &[
    ("", "All actions"),
    ("admin.", "Logins and admin"),
    ("customer.", "Customers"),
    ("key.", "Keys"),
    ("job.", "Jobs"),
    ("file.", "Files"),
    ("system.", "System"),
    ("file.processed", "Files processed"),
    ("file.failed", "Files failed"),
    ("file.retry", "Files retried"),
    ("key.export_secret", "Secret key exports"),
    ("key.revoke", "Key revocations"),
    ("admin.login_failed", "Failed logins"),
];

/// A compact search for a "Recent activity" section. It opens the audit log, limited to
/// `scope` (e.g. `("job", "3")`) on top of what the user picks. `hx-preserve` keeps what the
/// user is typing when a self-refreshing panel around it is swapped.
pub fn activity_search(scope: Option<(&str, String)>) -> Markup {
    let id = match &scope {
        Some((name, _)) => format!("activity-search-{name}"),
        None => "activity-search".to_owned(),
    };
    html! {
        form.activity-search #(id) hx-preserve="true" method="get" action="/audit" role="search" {
            @if let Some((name, value)) = &scope {
                input type="hidden" name=(name) value=(value);
            }
            input type="search" name="q" placeholder="Search activity…" aria-label="Search activity";
            select name="period" aria-label="Time" {
                @for (value, label, _) in PERIODS {
                    option value=(value) { (label) }
                }
            }
            select name="action" aria-label="Action" {
                @for (value, label) in ACTIONS {
                    option value=(value) { (label) }
                }
            }
            button type="submit" { "Search" }
        }
    }
}

/// Names for the IDs an audit event refers to.
pub trait AuditNames {
    fn customer(&self, id: i64) -> Option<&str>;
    fn job(&self, id: i64) -> Option<&str>;
}

pub fn audit_table(events: &[AuditEvent], names: &impl AuditNames) -> Markup {
    html! {
        @if events.is_empty() {
            p.muted { "No events." }
        } @else {
            table.audit {
                thead { tr { th { "Time" } th { "Actor" } th { "Action" } th { "Subject" } th { "Detail" } } }
                tbody {
                    @for event in events {
                        tr class=(action_class(&event.action)) {
                            td.nowrap { (timestamp(event.at)) }
                            td { (event.actor) }
                            td.nowrap { code { (event.action) } }
                            td {
                                @if let Some(id) = event.customer_id {
                                    a href={ "/customers/" (id) } { (names.customer(id).unwrap_or("customer")) }
                                    " "
                                }
                                @if let Some(id) = event.job_id {
                                    @match names.job(id) {
                                        Some(name) => a href={ "/jobs/" (id) } { "job " (name) },
                                        None => span.muted { "job #" (id) },
                                    }
                                    " "
                                }
                                @if let Some(fpr) = &event.key_fingerprint {
                                    a href={ "/keys/" (fpr) } { code { (key_id(fpr)) } }
                                }
                            }
                            td.detail { (event.detail) }
                        }
                    }
                }
            }
        }
    }
}

fn action_class(action: &str) -> &'static str {
    match action {
        "file.failed" | "admin.login_failed" | "job.pause" => "row-bad",
        "key.export_secret" | "key.delete" | "key.revoke" | "job.delete" => "row-warn",
        _ => "",
    }
}
