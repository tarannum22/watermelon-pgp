use axum::{
    extract::{Path, State},
    response::Redirect,
};
use maud::{Markup, Render, html};
use serde::Deserialize;
use watermelon_pgp_core::{audit::Actor, audit::Filter};

use super::{Names, keys};
use crate::{
    AppState,
    auth::{Authed, Posted},
    error::AppError,
    ui::{self, icons},
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
            (ui::page_header("Customers")
                .subtitle(html! { "Every partner you exchange files with. Keys and jobs always belong to a customer." }))
            div.dashboard-grid {
                (ui::panel(html! {
                    @if customers.is_empty() {
                        (ui::empty(icons::CUSTOMERS, "No customers yet", "Create the first one to add its keys and jobs.", None))
                    } @else {
                        div.table-wrap {
                            table.table {
                                thead { tr { th { "Name" } th.num { "Keys" } th.num { "Jobs" } th { "Created" } } }
                                tbody {
                                    @for customer in &customers {
                                        tr {
                                            td {
                                                a.strong href={ "/customers/" (customer.id) } { (customer.name) }
                                            }
                                            td.num { (keys.iter().filter(|k| k.customer_id == customer.id).count()) }
                                            td.num { (jobs.iter().filter(|j| j.customer_id == customer.id).count()) }
                                            td { (views::date(customer.created_at)) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }).flush())
                (ui::panel(html! {
                    form.form method="post" action="/customers" {
                        (views::csrf_field(&auth.csrf))
                        (ui::field("Name", Some("Usually the company, as you'd look for it later."), html! {
                            input type="text" name="name" required maxlength="200" placeholder="Alpine Outdoor GmbH";
                        }))
                        div.actions { (ui::button("Create customer").primary().icon(icons::PLUS)) }
                    }
                }).title("New customer").icon(icons::PLUS))
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
    let new_job = format!("/jobs/new?customer={}", customer.id);
    let all_activity = format!("/audit?customer={}", customer.id);
    Ok(views::layout(
        page,
        html! {
            (ui::page_header(&customer.name)
                .crumb("Customers", "/customers")
                .subtitle(html! { "Customer since " (views::date(customer.created_at)) })
                .actions(html! {
                    (ui::button("New job").primary().icon(icons::PLUS).href(&new_job))
                }))

            (ui::panel(keys::key_list(&keys.iter().collect::<Vec<_>>(), false))
                .title("Keys")
                .icon(icons::KEY)
                .flush())
            div.grid-2 {
                (keys::generate_form(&auth.csrf, &customer))
                (keys::import_form(&auth.csrf, &customer))
            }

            (ui::panel(html! {
                @if jobs.is_empty() {
                    (ui::empty(icons::JOBS, "No jobs yet", "A job watches a folder and encrypts or decrypts every file that arrives.",
                        Some(ui::button("New job").icon(icons::PLUS).href(&new_job).render())))
                } @else {
                    (super::jobs::job_table(&jobs, false))
                }
            }).title("Jobs").icon(icons::JOBS).flush())

            (ui::panel(views::audit_table(&events, &names))
                .title("Recent activity")
                .icon(icons::ACTIVITY)
                .actions(views::activity_search(Some(("customer", customer.id.to_string()))))
                .flush()
                .footer(ui::link_arrow(&all_activity, &format!("All activity for {}", customer.name))))
        },
    ))
}
