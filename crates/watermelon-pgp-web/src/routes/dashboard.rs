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
            h1 { "Dashboard" }
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
    let paused: Vec<&Job> = o
        .jobs
        .iter()
        .filter(|j| j.paused_reason.is_some())
        .collect();
    let erroring: Vec<&Job> = o
        .jobs
        .iter()
        .filter(|j| j.is_active() && j.last_error.is_some())
        .collect();
    let keys_attention: Vec<&KeyRecord> = o
        .keys
        .iter()
        .filter(|k| views::key_needs_attention(k))
        .collect();
    let names = Names::new(&o.customers, &o.jobs);
    html! {
        div #live hx-get="/dashboard/live" hx-trigger="every 10s" hx-swap="outerHTML" {
            div.tiles {
                a.tile href="/jobs" {
                    span.value { (running) }
                    span.label { "of " (o.jobs.len()) " jobs running" }
                }
                a.tile.bad[!paused.is_empty()] href="/jobs" {
                    span.value { (paused.len()) }
                    span.label { "paused jobs" }
                }
                a.tile href="/audit?action=file.processed" {
                    span.value { (o.processed) }
                    span.label { "files processed (24 h)" }
                }
                a.tile.bad[o.failed > 0] href="/audit?action=file.failed" {
                    span.value { (o.failed) }
                    span.label { "files failed (24 h)" }
                }
                a.tile.warn[!keys_attention.is_empty()] href="/keys" {
                    span.value { (o.keys.len()) }
                    span.label { "keys, " (keys_attention.len()) " need attention" }
                }
            }

            @if o.customers.is_empty() {
                section.card {
                    h2 { "Getting started" }
                    ol {
                        li { a href="/customers" { "Create a customer" } "." }
                        li { "Generate or import its keys." }
                        li { a href="/jobs/new" { "Create a job" } " that watches a folder." }
                    }
                }
            }

            @if !(paused.is_empty() && erroring.is_empty() && keys_attention.is_empty()) {
                section.card {
                    h2 { "Needs attention" }
                    ul.attention {
                        @for job in &paused {
                            li.bad {
                                a href={ "/jobs/" (job.id) } { "Job " (job.spec.name) }
                                " is paused: " (job.paused_reason.as_deref().unwrap_or(""))
                            }
                        }
                        @for job in &erroring {
                            li.warn {
                                a href={ "/jobs/" (job.id) } { "Job " (job.spec.name) }
                                ": " (job.last_error.as_deref().unwrap_or(""))
                            }
                        }
                        @for key in &keys_attention {
                            li.warn {
                                "Key " (views::key_link(key)) " (" (key.customer_name) ") "
                                (views::key_status(key))
                            }
                        }
                    }
                }
            }

            section {
                div.title-row {
                    h2 { "Recent activity" }
                    (views::activity_search(None))
                }
                (views::audit_table(&o.recent, &names))
                p { a href="/audit" { "Full audit log →" } }
            }
        }
    }
}
