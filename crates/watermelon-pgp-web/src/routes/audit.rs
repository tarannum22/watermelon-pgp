//! The audit log: filter by time, actor, action, subject and free text; page through it;
//! export what matches as CSV.

use axum::{
    extract::{Query, RawQuery, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Redirect, Response},
};
use maud::html;
use serde::{Deserialize, Serialize};
use watermelon_pgp_core::audit::{AuditEvent, Filter};

use super::{Names, parse_id};
use crate::{
    AppState,
    auth::Authed,
    error::AppError,
    ui::{self, Icon, Tone},
    views::{self, Nav},
};

const PAGE_SIZE: u32 = 100;
/// Upper bound for one CSV export; narrow the filter for more.
const EXPORT_LIMIT: u32 = 100_000;
const MAX_SEARCH_LEN: usize = 200;

/// The filter as it appears in the URL. Every field is optional; empty means "any".
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditQuery {
    /// Free-text search in subject and details.
    #[serde(skip_serializing_if = "String::is_empty")]
    q: String,
    /// `1h`, `24h`, `7d` or `30d`. Ignored when `from` or `to` is set.
    #[serde(skip_serializing_if = "String::is_empty")]
    period: String,
    /// First day, `YYYY-MM-DD`, UTC.
    #[serde(skip_serializing_if = "String::is_empty")]
    from: String,
    /// Last day (inclusive), `YYYY-MM-DD`, UTC.
    #[serde(skip_serializing_if = "String::is_empty")]
    to: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    actor: String,
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

impl AuditQuery {
    /// The core filter, plus a note for every part of the query that had to be ignored.
    fn filter(&self, limit: u32) -> (Filter, Vec<String>) {
        let mut problems = Vec::new();
        let mut date = |value: &str, label: &str| -> Option<i64> {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            let parsed = parse_date(value);
            if parsed.is_none() {
                problems.push(format!(
                    "Ignored the {label} date {value:?}: use YYYY-MM-DD."
                ));
            }
            parsed
        };
        let from = date(&self.from, "from");
        let to = date(&self.to, "to").map(|day| day + 86_400);
        let (since, until) = if from.is_some() || to.is_some() {
            (from, to)
        } else {
            let since = views::PERIODS
                .iter()
                .find(|(value, _, _)| !value.is_empty() && *value == self.period)
                .map(|(_, _, secs)| views::now() - secs);
            (since, None)
        };
        let text: String = self.q.trim().chars().take(MAX_SEARCH_LEN).collect();
        let filter = Filter {
            action: non_empty(&self.action),
            actor: non_empty(&self.actor),
            customer_id: parse_id(&self.customer),
            job_id: parse_id(&self.job),
            key_fingerprint: non_empty(&self.key).map(|k| k.to_uppercase()),
            since,
            until,
            text: Some(text).filter(|t| !t.is_empty()),
            before_id: parse_id(&self.before),
            limit,
        };
        (filter, problems)
    }

    fn url(&self, path: &str) -> String {
        match serde_html_form::to_string(self).unwrap_or_default() {
            query if query.is_empty() => path.to_owned(),
            query => format!("{path}?{query}"),
        }
    }

    fn first_page(&self) -> Self {
        Self {
            before: String::new(),
            ..self.clone()
        }
    }

    fn is_filtered(&self) -> bool {
        let first = self.first_page();
        !serde_html_form::to_string(&first)
            .unwrap_or_default()
            .is_empty()
    }
}

fn non_empty(value: &str) -> Option<String> {
    Some(value.trim().to_owned()).filter(|v| !v.is_empty())
}

/// Midnight UTC at the start of `YYYY-MM-DD`.
fn parse_date(value: &str) -> Option<i64> {
    let mut parts = value.splitn(3, '-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    Some(date.midnight().assume_utc().unix_timestamp())
}

/// One removable chip per active filter.
fn chips(query: &AuditQuery, names: &Names) -> Vec<(String, String)> {
    let mut chips = Vec::new();
    let mut add = |label: String, clear: fn(&mut AuditQuery)| {
        let mut without = query.first_page();
        clear(&mut without);
        chips.push((label, without.url("/audit")));
    };
    if !query.q.trim().is_empty() {
        add(format!("“{}”", query.q.trim()), |q| q.q.clear());
    }
    if !query.from.is_empty() || !query.to.is_empty() {
        let label = match (query.from.as_str(), query.to.as_str()) {
            (from, "") => format!("from {from}"),
            ("", to) => format!("until {to}"),
            (from, to) => format!("{from} – {to}"),
        };
        add(label, |q| {
            q.from.clear();
            q.to.clear();
        });
    } else if let Some((_, label, _)) = views::PERIODS
        .iter()
        .find(|(value, _, _)| !value.is_empty() && *value == query.period)
    {
        add((*label).to_owned(), |q| q.period.clear());
    }
    if let Some((_, label)) = views::ACTORS
        .iter()
        .find(|(value, _)| !value.is_empty() && *value == query.actor)
    {
        add((*label).to_owned(), |q| q.actor.clear());
    }
    if !query.action.is_empty() {
        let label = views::ACTIONS
            .iter()
            .find(|(value, _)| *value == query.action)
            .map_or(query.action.clone(), |(_, label)| (*label).to_owned());
        add(label, |q| q.action.clear());
    }
    if let Some(id) = parse_id(&query.customer) {
        let name = names
            .customers
            .get(&id)
            .cloned()
            .unwrap_or(format!("#{id}"));
        add(format!("customer {name}"), |q| q.customer.clear());
    }
    if let Some(id) = parse_id(&query.job) {
        let name = names.jobs.get(&id).cloned().unwrap_or(format!("#{id}"));
        add(format!("job {name}"), |q| q.job.clear());
    }
    if !query.key.trim().is_empty() {
        add(format!("key {}", views::key_id(query.key.trim())), |q| {
            q.key.clear()
        });
    }
    chips
}

/// The audit log. Filter forms send every field, empty or not (`?q=x&period=&from=…`); the
/// address bar shows only the filters in use: htmx is told which URL to push, and a plain form
/// submission is redirected to it.
pub async fn list(
    State(state): State<AppState>,
    auth: Authed,
    Query(query): Query<AuditQuery>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let clean = query.url("/audit");
    let has_empty = raw.as_deref().is_some_and(|raw| {
        raw.split('&')
            .any(|pair| pair.is_empty() || pair.ends_with('='))
    });
    let from_htmx = headers.contains_key("hx-request");
    if has_empty && !from_htmx {
        return Ok(Redirect::to(&clean).into_response());
    }
    let (filter, problems) = query.filter(PAGE_SIZE);
    let (events, total, customers, jobs) = state
        .vault(move |vault| {
            Ok((
                vault.query_audit(&filter)?,
                vault.count_audit(&filter)?,
                vault.customers()?,
                vault.jobs()?,
            ))
        })
        .await?;
    let names = Names::new(&customers, &jobs);
    let chips = chips(&query, &names);
    let older = (events.len() == PAGE_SIZE as usize)
        .then(|| events.last())
        .flatten()
        .map(|last| {
            AuditQuery {
                before: last.id.to_string(),
                ..query.clone()
            }
            .url("/audit")
        });
    let export = query.first_page().url("/audit.csv");
    let custom_range = !query.from.is_empty() || !query.to.is_empty();
    let page = state.page(&auth, "Audit log", Nav::Audit);
    let newest = (!query.before.is_empty()).then(|| query.first_page().url("/audit"));
    let page = views::layout(
        page,
        html! {
            (ui::page_header("Audit log")
                .subtitle(html! { "Everything that happened: logins, key and job changes, every file processed. Append-only." })
                .actions(html! { (ui::button("Export CSV").icon(Icon::Download).href(&export).download()) }))
            // Live filtering with htmx: only the results are swapped, and the URL follows, so
            // a filtered view can be bookmarked. Without JavaScript the Filter button does it.
            (ui::panel(html! {
                form.toolbar method="get" action="/audit"
                    hx-get="/audit" hx-target="#audit-results" hx-select="#audit-results"
                    hx-swap="outerHTML" hx-push-url="true" hx-sync="this:replace"
                    hx-trigger="submit, change, input delay:400ms from:input[name=q]" {
                    div.wide {
                        (ui::field("Search", None, html! {
                            span.search {
                                (ui::icon(Icon::Search))
                                input type="search" name="q" value=(query.q) maxlength=(MAX_SEARCH_LEN)
                                    placeholder="Customer, job, key, user ID, file name, details…" autocomplete="off";
                            }
                        }))
                    }
                    (ui::field("Time", None, html! {
                        select name="period" {
                            @for (value, label, _) in views::PERIODS {
                                option value=(value) selected[!custom_range && query.period == *value] { (label) }
                            }
                        }
                    }))
                    (ui::field("From (UTC)", None, html! { input type="date" name="from" value=(query.from); }))
                    (ui::field("To (UTC)", None, html! { input type="date" name="to" value=(query.to); }))
                    (ui::field("Who", None, html! {
                        select name="actor" {
                            @for (value, label) in views::ACTORS {
                                option value=(value) selected[query.actor == *value] { (label) }
                            }
                        }
                    }))
                    (ui::field("Action", None, html! {
                        select name="action" {
                            @for (value, label) in views::ACTIONS {
                                option value=(value) selected[query.action == *value] { (label) }
                            }
                            @if !query.action.is_empty() && !views::ACTIONS.iter().any(|(v, _)| *v == query.action) {
                                option value=(query.action) selected { (query.action) }
                            }
                        }
                    }))
                    (ui::field("Customer", None, html! {
                        select name="customer" {
                            option value="" { "All customers" }
                            @for customer in &customers {
                                option value=(customer.id) selected[parse_id(&query.customer) == Some(customer.id)] { (customer.name) }
                            }
                        }
                    }))
                    (ui::field("Job", None, html! {
                        select name="job" {
                            option value="" { "All jobs" }
                            @for job in &jobs {
                                option value=(job.id) selected[parse_id(&query.job) == Some(job.id)] { (job.customer_name) " / " (job.spec.name) }
                            }
                        }
                    }))
                    @if !query.key.is_empty() {
                        input type="hidden" name="key" value=(query.key);
                    }
                    div { (ui::button("Filter").icon(Icon::Filter)) }
                }
            }).title("Filters").icon(Icon::Filter))

            div #audit-results.stack {
                @for problem in &problems {
                    (ui::alert(Tone::Bad, None, html! { (problem) }))
                }
                (ui::panel(views::audit_table(&events, &names))
                    .description(html! {
                        span.summary {
                            strong { (total) " " (if total == 1 { "event" } else { "events" }) }
                            @if !chips.is_empty() {
                                " matching "
                                @for (label, without) in &chips {
                                    (ui::removable_chip(without, label))
                                }
                            }
                            @if query.is_filtered() {
                                a href="/audit" { "Clear all" }
                            }
                        }
                    })
                    .title("Events")
                    .icon(Icon::Audit)
                    .flush()
                    .footer(html! {
                        span { "Newest first, " (PAGE_SIZE) " per page" }
                        nav.paging {
                            @if let Some(href) = &newest { a href=(href) { "← Newest" } }
                            @if let Some(href) = &older { a href=(href) { "Older →" } }
                        }
                    }))
            }
        },
    );
    let mut response = page.into_response();
    if from_htmx && let Ok(url) = HeaderValue::from_str(&clean) {
        response.headers_mut().insert("hx-push-url", url);
    }
    Ok(response)
}

/// Everything matching the filter as CSV, oldest first, for audits and spreadsheets.
pub async fn export(
    State(state): State<AppState>,
    _auth: Authed,
    Query(query): Query<AuditQuery>,
) -> Result<Response, AppError> {
    let (filter, _) = query.first_page().filter(EXPORT_LIMIT);
    let (events, customers, jobs) = state
        .vault(move |vault| {
            Ok((
                vault.query_audit(&filter)?,
                vault.customers()?,
                vault.jobs()?,
            ))
        })
        .await?;
    let names = Names::new(&customers, &jobs);
    let mut csv = String::from("id,time_utc,actor,action,customer,job,key,detail\r\n");
    for event in events.iter().rev() {
        csv.push_str(&csv_row(event, &names));
    }
    let stamp = time::OffsetDateTime::now_utc();
    let file_name = format!(
        "watermelon-audit-{:04}{:02}{:02}-{:02}{:02}.csv",
        stamp.year(),
        u8::from(stamp.month()),
        stamp.day(),
        stamp.hour(),
        stamp.minute()
    );
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file_name}\""),
            ),
        ],
        csv,
    )
        .into_response())
}

fn csv_row(event: &AuditEvent, names: &Names) -> String {
    let customer = event.customer_id.map(|id| {
        names
            .customers
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("#{id}"))
    });
    let job = event.job_id.map(|id| {
        names
            .jobs
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("#{id}"))
    });
    let time = time::OffsetDateTime::from_unix_timestamp(event.at)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| event.at.to_string());
    let fields = [
        event.id.to_string(),
        time,
        event.actor.clone(),
        event.action.clone(),
        customer.unwrap_or_default(),
        job.unwrap_or_default(),
        event.key_fingerprint.clone().unwrap_or_default(),
        event.detail.clone(),
    ];
    let cells: Vec<String> = fields.iter().map(|field| csv_cell(field)).collect();
    format!("{}\r\n", cells.join(","))
}

/// Quote a CSV cell. Cells a spreadsheet would run as a formula get a leading `'`: details
/// can contain names and file names that came from outside.
fn csv_cell(value: &str) -> String {
    let value = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_cells_are_quoted_and_defused() {
        assert_eq!(csv_cell("plain"), "\"plain\"");
        assert_eq!(csv_cell("say \"hi\", ok"), "\"say \"\"hi\"\", ok\"");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("-1+1"), "\"'-1+1\"");
        assert_eq!(csv_cell("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn dates_and_periods_become_time_bounds() {
        assert_eq!(parse_date("1970-01-02"), Some(86_400));
        assert_eq!(parse_date("2026-02-30"), None);
        assert_eq!(parse_date("yesterday"), None);

        let custom = AuditQuery {
            from: "1970-01-02".into(),
            to: "1970-01-02".into(),
            period: "24h".into(),
            ..AuditQuery::default()
        };
        let (filter, problems) = custom.filter(10);
        assert_eq!(
            (filter.since, filter.until),
            (Some(86_400), Some(2 * 86_400))
        );
        assert!(problems.is_empty(), "the range wins over the period");

        let recent = AuditQuery {
            period: "1h".into(),
            ..AuditQuery::default()
        };
        let since = recent.filter(10).0.since.unwrap();
        assert!((views::now() - 3600 - since).abs() <= 1);

        let bad = AuditQuery {
            from: "31.12.2026".into(),
            ..AuditQuery::default()
        };
        let (filter, problems) = bad.filter(10);
        assert_eq!(filter.since, None);
        assert_eq!(problems.len(), 1);
    }
}
