use axum::extract::{Query, State};
use maud::{Markup, html};
use serde::{Deserialize, Serialize};
use watermelon_pgp_core::audit::Filter;

use super::{Names, parse_id};
use crate::{
    AppState,
    auth::Authed,
    error::AppError,
    views::{self, Nav},
};

const PAGE_SIZE: u32 = 100;

/// Action filter choices: categories, then the actions worth finding on their own.
const ACTIONS: &[(&str, &str)] = &[
    ("", "All actions"),
    ("admin.", "Logins and admin"),
    ("customer.", "Customers"),
    ("key.", "Keys"),
    ("job.", "Jobs"),
    ("file.", "Files"),
    ("system.", "System"),
    ("file.processed", "Files processed"),
    ("file.failed", "Files failed"),
    ("key.export_secret", "Secret key exports"),
    ("key.revoke", "Key revocations"),
    ("admin.login_failed", "Failed logins"),
];

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditQuery {
    #[serde(skip_serializing_if = "String::is_empty")]
    action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    customer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    job: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    before: String,
}

pub async fn list(
    State(state): State<AppState>,
    auth: Authed,
    Query(query): Query<AuditQuery>,
) -> Result<Markup, AppError> {
    let filter = Filter {
        action: Some(query.action.trim().to_owned()).filter(|a| !a.is_empty()),
        customer_id: parse_id(&query.customer),
        job_id: parse_id(&query.job),
        key_fingerprint: Some(query.key.trim().to_uppercase()).filter(|k| !k.is_empty()),
        before_id: parse_id(&query.before),
        limit: PAGE_SIZE,
    };
    let (events, customers, jobs) = {
        let filter = filter.clone();
        state
            .vault(move |vault| {
                Ok((
                    vault.query_audit(&filter)?,
                    vault.customers()?,
                    vault.jobs()?,
                ))
            })
            .await?
    };
    let names = Names::new(&customers, &jobs);
    let older = (events.len() == PAGE_SIZE as usize)
        .then(|| events.last().map(|e| e.id))
        .flatten()
        .map(|id| {
            let next = AuditQuery {
                before: id.to_string(),
                ..query_without_paging(&query)
            };
            format!(
                "/audit?{}",
                serde_html_form::to_string(&next).unwrap_or_default()
            )
        });
    let page = state.page(&auth, "Audit log", Nav::Audit);
    Ok(views::layout(
        page,
        html! {
            h1 { "Audit log" }
            form.filters method="get" action="/audit" {
                label {
                    "Action"
                    select name="action" {
                        @for (value, label) in ACTIONS {
                            option value=(value) selected[query.action == *value] { (label) }
                        }
                        @if !query.action.is_empty() && !ACTIONS.iter().any(|(v, _)| *v == query.action) {
                            option value=(query.action) selected { (query.action) }
                        }
                    }
                }
                label {
                    "Customer"
                    select name="customer" {
                        option value="" { "All customers" }
                        @for customer in &customers {
                            option value=(customer.id) selected[filter.customer_id == Some(customer.id)] { (customer.name) }
                        }
                    }
                }
                label {
                    "Job"
                    select name="job" {
                        option value="" { "All jobs" }
                        @for job in &jobs {
                            option value=(job.id) selected[filter.job_id == Some(job.id)] { (job.customer_name) " / " (job.spec.name) }
                        }
                    }
                }
                label { "Key fingerprint" input type="text" name="key" value=(query.key) size="20"; }
                button type="submit" { "Filter" }
                a href="/audit" { "Reset" }
            }
            (views::audit_table(&events, &names))
            nav.paging {
                @if !query.before.is_empty() {
                    a href={ "/audit?" (serde_html_form::to_string(query_without_paging(&query)).unwrap_or_default()) } { "← Newest" }
                }
                @if let Some(href) = older {
                    a href=(href) { "Older →" }
                }
            }
        },
    ))
}

fn query_without_paging(query: &AuditQuery) -> AuditQuery {
    AuditQuery {
        action: query.action.clone(),
        customer: query.customer.clone(),
        job: query.job.clone(),
        key: query.key.clone(),
        before: String::new(),
    }
}
