//! Page layout and small rendering helpers shared by the routes.

use axum::http::StatusCode;
use maud::{DOCTYPE, Markup, Render, html};
use watermelon_pgp_core::{audit::AuditEvent, jobs::Job, store::KeyRecord};

use crate::{
    auth::{CSRF_FIELD, Flash},
    ui::{self, Theme, Tone, icons},
};

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
    #[cfg(feature = "evaluation")]
    Design,
}

/// What every logged-in page needs besides its content.
pub struct Page<'a> {
    pub title: &'a str,
    pub nav: Nav,
    pub csrf: &'a str,
    pub theme: Theme,
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
        title { (title) " · WatermelonPGP" }
        link rel="icon" href=(asset("logo.svg")) type="image/svg+xml";
        link rel="preload" href="/static/geist-1.9.0.woff2" as="font" type="font/woff2" crossorigin;
        link rel="stylesheet" href=(asset("app.css"));
        script src=(asset("htmx.min.js")) defer {}
        script src=(asset("app.js")) defer {}
    }
}

fn brand(version: bool) -> Markup {
    html! {
        a.brand href="/" {
            img src=(asset("logo.svg")) alt="" width="32" height="32";
            span.brand-name {
                strong { "Watermelon" span { "PGP" } }
                @if version { small { "v" (VERSION) } }
            }
        }
    }
}

/// A main navigation entry: page, URL, label, icon.
type NavItem = (Nav, &'static str, &'static str, &'static str);

/// Main navigation, in titled sections.
const NAV_SECTIONS: &[(&str, &[NavItem])] = &[
    (
        "Operations",
        &[
            (Nav::Dashboard, "/", "Dashboard", icons::DASHBOARD),
            (Nav::Jobs, "/jobs", "Jobs", icons::JOBS),
            (Nav::Audit, "/audit", "Audit log", icons::AUDIT),
        ],
    ),
    (
        "Key management",
        &[
            (Nav::Customers, "/customers", "Customers", icons::CUSTOMERS),
            (Nav::Keys, "/keys", "Keys", icons::KEY),
        ],
    ),
    (
        "System",
        &[
            (Nav::Settings, "/settings", "Settings", icons::SETTINGS),
            #[cfg(feature = "evaluation")]
            (Nav::Design, "/design", "Design system", icons::PALETTE),
        ],
    ),
];

/// The logged-in shell: sidebar navigation, top bar with search, the page, a footer.
pub fn layout(page: Page<'_>, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=[page.theme.attribute()] {
            head { (head(page.title)) }
            body hx-boost="true" {
                div.shell {
                    aside.sidebar {
                        (brand(true))
                        nav.nav aria-label="Main" {
                            @for (heading, items) in NAV_SECTIONS {
                                span.nav-label { (heading) }
                                @for (nav, href, label, svg) in *items {
                                    a.nav-item href=(href) aria-current=[(*nav == page.nav).then_some("page")] {
                                        (ui::icon(svg)) span.label { (label) }
                                    }
                                }
                            }
                        }
                        div.sidebar-foot {
                            @if cfg!(feature = "evaluation") {
                                a.eval-badge href="/design" title="Built with the evaluation feature: not for production" {
                                    (ui::icon(icons::PALETTE)) "Evaluation build"
                                }
                            }
                            (ui::theme_switch(csrf_field(page.csrf), page.theme))
                            form method="post" action="/logout" {
                                (csrf_field(page.csrf))
                                (ui::button("Log out").ghost().block().icon(icons::LOGOUT))
                            }
                        }
                    }
                    div.main-col {
                        div.topbar {
                            form method="get" action="/audit" role="search" {
                                (ui::search_input("q", "", "Search activity: customer, job, key, file…", "Search activity"))
                            }
                            span.spacer {}
                            span.hide-sm { (ui::button("New job").icon(icons::PLUS).href("/jobs/new")) }
                        }
                        main.content #main {
                            @if let Some(flash) = &page.flash {
                                (flash_message(flash))
                            }
                            (content)
                        }
                        footer.page-foot { "WatermelonPGP " (VERSION) }
                    }
                }
            }
        }
    }
}

/// A page outside the logged-in shell (login, errors).
pub fn bare(title: &str, theme: Theme, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=[theme.attribute()] {
            head { (head(title)) }
            body {
                main.bare {
                    div.bare-card {
                        (brand(false))
                        (content)
                    }
                }
            }
        }
    }
}

pub fn error_page(status: StatusCode, message: &str) -> Markup {
    let reason = status.canonical_reason().unwrap_or("Error");
    bare(
        reason,
        Theme::System,
        ui::panel(html! {
            h1 { (status.as_u16()) " " (reason) }
            (ui::alert(Tone::Bad, None, html! { (message) }))
            (ui::link_arrow("/", "Back to the dashboard"))
        })
        .render(),
    )
}

pub fn flash_message(flash: &Flash) -> Markup {
    match flash {
        Flash::Success(message) => ui::alert(Tone::Good, None, html! { (message) }),
        Flash::Error(message) => ui::alert(Tone::Bad, None, html! { (message) }),
    }
}

pub fn csrf_field(csrf: &str) -> Markup {
    html! { input type="hidden" name=(CSRF_FIELD) value=(csrf); }
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

/// The long key ID: the last 16 hex digits.
pub fn key_id(fpr: &str) -> &str {
    &fpr[fpr.len().saturating_sub(16)..]
}

pub fn key_link(key: &KeyRecord) -> Markup {
    html! {
        a href={ "/keys/" (key.fingerprint) } { (key.label()) }
        " " code { (key_id(&key.fingerprint)) }
    }
}

/// A user ID split into name and email: `Alpine <pgp@alpine.example>` →
/// (`Alpine`, `pgp@alpine.example`). IDs without an email are all name.
pub fn uid_parts(uid: &str) -> (&str, Option<&str>) {
    match uid
        .trim_end()
        .strip_suffix('>')
        .and_then(|rest| rest.rsplit_once('<'))
    {
        Some((name, email)) if !name.trim().is_empty() => (name.trim(), Some(email)),
        Some((_, email)) => (email, None),
        None => (uid, None),
    }
}

/// Revoked / expired / expiring soon / valid.
pub fn key_status(key: &KeyRecord) -> Markup {
    let (tone, text) = key_state(key);
    ui::pill(tone, &text)
}

pub fn key_state(key: &KeyRecord) -> (Tone, String) {
    let now = now();
    match key.expires_at {
        _ if key.revoked => (Tone::Bad, "revoked".into()),
        Some(at) if at <= now => (Tone::Bad, "expired".into()),
        Some(at) if at - now <= EXPIRY_WARNING_DAYS * 86_400 => (
            Tone::Warn,
            format!("expires in {} days", (at - now) / 86_400),
        ),
        _ => (Tone::Good, "valid".into()),
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
        span.tags {
            @if key.can_encrypt { (ui::tag("encrypt", "can encrypt", false)) }
            @if key.can_sign { (ui::tag("sign", "can sign", false)) }
            @if key.has_secret { (ui::tag("secret", "we hold the secret key", true)) }
        }
    }
}

pub fn job_state(job: &Job) -> Markup {
    match (&job.paused_reason, job.enabled) {
        (Some(reason), _) => ui::pill_titled(Tone::Bad, "paused", reason),
        (None, true) => match &job.last_error {
            Some(error) => ui::pill_titled(Tone::Warn, "error", error),
            None => ui::pill(Tone::Good, "running"),
        },
        (None, false) => ui::pill(Tone::Neutral, "disabled"),
    }
}

pub fn kind_name(job: &Job) -> &'static str {
    match job.spec.kind {
        watermelon_pgp_core::jobs::JobKind::Encrypt => "encrypt",
        watermelon_pgp_core::jobs::JobKind::Decrypt => "decrypt",
    }
}

/// "encrypt" or "decrypt", with a lock icon.
pub fn kind_tag(job: &Job) -> Markup {
    let svg = match job.spec.kind {
        watermelon_pgp_core::jobs::JobKind::Encrypt => icons::LOCK,
        watermelon_pgp_core::jobs::JobKind::Decrypt => icons::UNLOCK,
    };
    html! { span.tag.kind { (ui::icon_with(svg, "icon sm")) (kind_name(job)) } }
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
        form.inline-search #(id) hx-preserve="true" method="get" action="/audit" role="search" {
            @if let Some((name, value)) = &scope {
                input type="hidden" name=(name) value=(value);
            }
            (ui::search_input("q", "", "Search activity…", "Search activity"))
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
            (ui::button("Search").small())
        }
    }
}

/// Names for the IDs an audit event refers to.
pub trait AuditNames {
    fn customer(&self, id: i64) -> Option<&str>;
    fn job(&self, id: i64) -> Option<&str>;
}

/// Audit events as a table, for use inside a flush panel.
pub fn audit_table(events: &[AuditEvent], names: &impl AuditNames) -> Markup {
    html! {
        @if events.is_empty() {
            (ui::empty(icons::AUDIT, "No events", "Nothing recorded matches.", None))
        } @else {
            div.table-wrap {
                table.table.audit {
                    thead { tr { th { "Time" } th { "Actor" } th { "Action" } th { "Subject" } th { "Detail" } } }
                    tbody {
                        @for event in events {
                            tr class=(action_tone(&event.action).class()) {
                                td.nowrap { (timestamp(event.at)) }
                                td.mono { (event.actor) }
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
                                td.detail { span.clamp title=(event.detail) { (event.detail) } }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Rows worth noticing: failures in red, irreversible or sensitive actions in amber.
fn action_tone(action: &str) -> Tone {
    match action {
        "file.failed" | "admin.login_failed" | "job.pause" => Tone::Bad,
        "key.export_secret" | "key.delete" | "key.revoke" | "job.delete" => Tone::Warn,
        _ => Tone::Neutral,
    }
}

#[cfg(test)]
mod tests {
    use super::uid_parts;

    #[test]
    fn user_ids_split_into_name_and_email() {
        assert_eq!(
            uid_parts("Alpine <pgp@alpine.example>"),
            ("Alpine", Some("pgp@alpine.example"))
        );
        assert_eq!(
            uid_parts("<pgp@alpine.example>"),
            ("pgp@alpine.example", None)
        );
        assert_eq!(uid_parts("Just a name"), ("Just a name", None));
    }
}
