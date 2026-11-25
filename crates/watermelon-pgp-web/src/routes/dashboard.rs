use axum::extract::State;
use maud::{Markup, html};
use watermelon_pgp_core::{
    audit::{Action, AuditEvent},
    jobs::Job,
    store::{Customer, KeyRecord},
};

use super::Names;
use crate::{
    AppState,
    auth::{Authed, Watching},
    error::AppError,
    ui::{self, Icon, Stat, Tone},
    views::{self, Nav},
};

struct Overview {
    customers: Vec<Customer>,
    jobs: Vec<Job>,
    keys: Vec<KeyRecord>,
    processed: u64,
    failed: u64,
    recent: Vec<AuditEvent>,
}

async fn overview(state: &AppState) -> Result<Overview, AppError> {
    let since = views::now() - 86_400;
    state
        .vault(move |vault| {
            Ok(Overview {
                customers: vault.customers()?,
                jobs: vault.jobs()?,
                keys: vault.keys(None)?,
                processed: vault.count_audit_since(Action::FileProcessed, since)?,
                failed: vault.count_audit_since(Action::FileFailed, since)?,
                recent: vault.audit_events(12)?,
            })
        })
        .await
}

pub async fn show(State(state): State<AppState>, auth: Authed) -> Result<Markup, AppError> {
    let overview = overview(&state).await?;
    let page = state.page(&auth, "Dashboard", Nav::Dashboard);
    Ok(views::layout(
        page,
        html! {
            (ui::page_header("Dashboard")
                .subtitle(html! { "Jobs, files and keys at a glance. Updates every 10 seconds." })
                .actions(html! {
                    (ui::button("Audit log").icon(Icon::Audit).href("/audit"))
                    (ui::button("New job").primary().icon(Icon::Plus).href("/jobs/new"))
                }))
            (live_panel(&overview))
        },
    ))
}

/// The self-refreshing part of the dashboard.
pub async fn live(
    State(state): State<AppState>,
    Watching(_): Watching,
) -> Result<Markup, AppError> {
    Ok(live_panel(&overview(&state).await?))
}

fn live_panel(o: &Overview) -> Markup {
    let running = o.jobs.iter().filter(|j| j.is_active()).count();
    let paused = o.jobs.iter().filter(|j| j.paused_reason.is_some()).count();
    let keys_attention = o
        .keys
        .iter()
        .filter(|k| views::key_needs_attention(k))
        .count();
    let attention = views::attention(&o.jobs, &o.keys);
    let names = Names::new(&o.customers, &o.jobs);
    let stats = [
        Stat {
            href: "/jobs",
            icon: Icon::Jobs,
            label: "Jobs running",
            value: running.to_string(),
            detail: format!("of {} jobs", o.jobs.len()),
            tone: Tone::Neutral,
        },
        Stat {
            href: "/jobs",
            icon: Icon::Pause,
            label: "Paused jobs",
            value: paused.to_string(),
            detail: if paused == 0 {
                "none".into()
            } else {
                "need a look".into()
            },
            tone: if paused == 0 {
                Tone::Neutral
            } else {
                Tone::Bad
            },
        },
        Stat {
            href: "/audit?action=file.processed&period=24h",
            icon: Icon::FileCheck,
            label: "Files processed",
            value: o.processed.to_string(),
            detail: "last 24 hours".into(),
            tone: Tone::Neutral,
        },
        Stat {
            href: "/audit?action=file.failed&period=24h",
            icon: Icon::FileX,
            label: "Files failed",
            value: o.failed.to_string(),
            detail: "last 24 hours".into(),
            tone: if o.failed > 0 {
                Tone::Bad
            } else {
                Tone::Neutral
            },
        },
        Stat {
            href: "/keys",
            icon: Icon::Key,
            label: "Keys",
            value: o.keys.len().to_string(),
            detail: format!("{keys_attention} need attention"),
            tone: if keys_attention == 0 {
                Tone::Neutral
            } else {
                Tone::Warn
            },
        },
    ];
    html! {
        div #live.stack hx-get="/dashboard/live" hx-trigger="every 10s" hx-swap="outerHTML" {
            div.stats { @for stat in &stats { (stat) } }

            @if o.customers.is_empty() {
                (ui::panel(html! {
                    ol.getting-started {
                        li { a href="/customers" { "Create a customer" } " for each partner you exchange files with." }
                        li { "Generate or import its keys." }
                        li { a href="/jobs/new" { "Create a job" } " that watches a folder and encrypts or decrypts what arrives." }
                    }
                }).title("Getting started").icon(Icon::Info))
            }

            @if attention.is_empty() {
                (ui::alert(Tone::Good, Some("All clear"), html! { "No paused jobs, job errors or keys about to expire." }))
            } @else {
                (ui::panel(ui::notice_list(&attention))
                    .title("Needs attention")
                    .icon(Icon::Warning)
                    .tone(Tone::Warn)
                    .flush())
            }

            (ui::panel(views::audit_table(&o.recent, &names))
                .title("Recent activity")
                .icon(Icon::Activity)
                .actions(views::activity_search(None))
                .flush()
                .footer(html! {
                    span { "Latest " (o.recent.len()) " events" }
                    (ui::link_arrow("/audit", "Full audit log"))
                }))
        }
    }
}
