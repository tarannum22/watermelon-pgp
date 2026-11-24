use axum::{
    extract::{Path, State},
    response::Redirect,
};
use maud::{Markup, html};
use serde::Deserialize;
use watermelon_pgp_core::{audit::Actor, audit::Filter};

use super::{Names, keys};
use crate::{
    AppState,
    auth::{Authed, Posted},
    error::AppError,
    views::{self, Nav},
};

pub async fn list(State(state): State<AppState>, auth: Authed) -> Result<Markup, AppError> {
    let (customers, keys, jobs) = state
        .vault(|vault| Ok((vault.customers()?, vault.keys(None)?, vault.jobs()?)))
        .await?;
    let page = state.page(&auth, "Customers", Nav::Customers);
    Ok(views::layout(
        page,
        html! {
            h1 { "Customers" }
            @if customers.is_empty() {
                p.muted { "No customers yet. Keys and jobs always belong to a customer." }
            } @else {
                table {
                    thead { tr { th { "Name" } th.num { "Keys" } th.num { "Jobs" } th { "Created" } } }
                    tbody {
                        @for customer in &customers {
                            tr {
                                td { a href={ "/customers/" (customer.id) } { (customer.name) } }
                                td.num { (keys.iter().filter(|k| k.customer_id == customer.id).count()) }
                                td.num { (jobs.iter().filter(|j| j.customer_id == customer.id).count()) }
                                td { (views::date(customer.created_at)) }
                            }
                        }
                    }
                }
            }
            section.card {
                h2 { "New customer" }
                form.inline method="post" action="/customers" {
                    (views::csrf_field(&auth.csrf))
                    label { "Name" input type="text" name="name" required maxlength="200"; }
                    button.primary type="submit" { "Create" }
                }
            }
        },
    ))
}

#[derive(Deserialize)]
pub struct NewCustomer {
    name: String,
}

pub async fn create(State(state): State<AppState>, posted: Posted<NewCustomer>) -> Redirect {
    let name = posted.form.name;
    match state
        .vault(move |vault| vault.create_customer(Actor::Admin, &name))
        .await
    {
        Ok(customer) => state.done(
            &posted.auth,
            &format!("/customers/{}", customer.id),
            Ok(format!("Created customer {}.", customer.name)),
        ),
        Err(e) => state.done(&posted.auth, "/customers", Err(e)),
    }
}

pub async fn show(
    State(state): State<AppState>,
    auth: Authed,
    Path(id): Path<i64>,
) -> Result<Markup, AppError> {
    let (customer, keys, jobs, events, customers) = state
        .vault(move |vault| {
            let customer = vault.customer_by_id(id)?;
            let jobs: Vec<_> = vault
                .jobs()?
                .into_iter()
                .filter(|j| j.customer_id == id)
                .collect();
            let events = vault.query_audit(&Filter {
                customer_id: Some(id),
                limit: 15,
                ..Filter::default()
            })?;
            Ok((
                customer,
                vault.keys(Some(id))?,
                jobs,
                events,
                vault.customers()?,
            ))
        })
        .await?;
    let names = Names::new(&customers, &jobs);
    let page = state.page(&auth, &customer.name, Nav::Customers);
    Ok(views::layout(
        page,
        html! {
            p.crumbs { a href="/customers" { "Customers" } " /" }
            h1 { (customer.name) }

            section {
                h2 { "Keys" }
                (keys::key_table(&keys, false))
            }
            div.columns {
                (keys::generate_form(&auth.csrf, &customer))
                (keys::import_form(&auth.csrf, &customer))
            }

            section {
                h2 { "Jobs" }
                @if jobs.is_empty() {
                    p.muted { "No jobs yet." }
                } @else {
                    table {
                        thead { tr { th { "Name" } th { "Kind" } th { "State" } th { "Input → output" } } }
                        tbody {
                            @for job in &jobs {
                                tr {
                                    td { a href={ "/jobs/" (job.id) } { (job.spec.name) } }
                                    td { (views::kind_name(job)) }
                                    td { (views::job_state(job)) }
                                    td.paths { code { (job.spec.input_dir.display()) } " → " code { (job.spec.output_dir.display()) } }
                                }
                            }
                        }
                    }
                }
                p { a.button href={ "/jobs/new?customer=" (customer.id) } { "New job" } }
            }

            section {
                h2 { "Recent activity" }
                (views::audit_table(&events, &names))
                p { a href={ "/audit?customer=" (customer.id) } { "All activity for " (customer.name) " →" } }
            }
        },
    ))
}
