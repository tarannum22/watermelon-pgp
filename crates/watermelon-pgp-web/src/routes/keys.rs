use axum::{
    extract::{Multipart, Path, State},
    http::header,
    response::{IntoResponse, Redirect, Response},
};
use maud::{Markup, html};
use serde::Deserialize;
use watermelon_pgp_core::{
    audit::{Actor, Filter},
    crypto::{self, Algorithm},
    store::{Customer, KeyRecord},
};
use zeroize::Zeroizing;

use super::{Confirmed, Empty, Names};
use crate::{
    AppState,
    auth::{Authed, CSRF_FIELD, Posted},
    error::AppError,
    views::{self, Nav},
};

/// Minimum passphrase length for exported secret keys.
const MIN_EXPORT_PASSPHRASE_LEN: usize = 8;

pub fn key_table(keys: &[KeyRecord], with_customer: bool) -> Markup {
    html! {
        @if keys.is_empty() {
            p.muted { "No keys yet." }
        } @else {
            table {
                thead {
                    tr {
                        th { "Key" }
                        @if with_customer { th { "Customer" } }
                        th { "Algorithm" }
                        th { "Can" }
                        th { "Created" }
                        th { "Expires" }
                        th { "Status" }
                    }
                }
                tbody {
                    @for key in keys {
                        tr {
                            td { (views::key_link(key)) }
                            @if with_customer {
                                td { a href={ "/customers/" (key.customer_id) } { (key.customer_name) } }
                            }
                            td { (key.algorithm) }
                            td { (views::key_capabilities(key)) }
                            td { (views::date(key.created_at)) }
                            td { @match key.expires_at { Some(at) => (views::date(at)), None => span.muted { "never" } } }
                            td { (views::key_status(key)) }
                        }
                    }
                }
            }
        }
    }
}

pub fn generate_form(csrf: &str, customer: &Customer) -> Markup {
    html! {
        section.card {
            h2 { "Generate a key" }
            form.stack method="post" action={ "/customers/" (customer.id) "/keys/generate" } {
                (views::csrf_field(csrf))
                label {
                    "User ID"
                    input type="text" name="user_id" required maxlength="500"
                        placeholder={ (customer.name) " <pgp@example.com>" };
                }
                label {
                    "Algorithm"
                    select name="algorithm" {
                        option value="curve25519" selected { "Ed25519 + Cv25519 (recommended)" }
                        option value="rsa4096" { "RSA 4096 (for older partners; slow to generate)" }
                    }
                }
                button.primary type="submit" { "Generate" }
            }
        }
    }
}

pub fn import_form(csrf: &str, customer: &Customer) -> Markup {
    html! {
        section.card {
            h2 { "Import keys" }
            form.stack method="post" action={ "/customers/" (customer.id) "/keys/import" }
                enctype="multipart/form-data" {
                (views::csrf_field(csrf))
                label { "Key file (armored or binary)" input type="file" name="file"; }
                label {
                    "…or paste an armored key"
                    textarea name="armored" rows="4" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" {}
                }
                label {
                    "Passphrase (only for protected secret keys)"
                    input type="password" name="passphrase" autocomplete="off";
                }
                p.hint { "Secret keys are re-encrypted under the master key; their passphrase is not kept." }
                button.primary type="submit" { "Import" }
            }
        }
    }
}

pub async fn list(State(state): State<AppState>, auth: Authed) -> Result<Markup, AppError> {
    let keys = state.vault(|vault| vault.keys(None)).await?;
    let page = state.page(&auth, "Keys", Nav::Keys);
    Ok(views::layout(
        page,
        html! {
            h1 { "Keys" }
            (key_table(&keys, true))
            p.hint { "To add keys, open a " a href="/customers" { "customer" } "." }
        },
    ))
}

pub async fn show(
    State(state): State<AppState>,
    auth: Authed,
    Path(fpr): Path<String>,
) -> Result<Markup, AppError> {
    let (key, used_by, events, customers, jobs) = state
        .vault(move |vault| {
            let key = vault.find_key(&fpr)?;
            let events = vault.query_audit(&Filter {
                key_fingerprint: Some(key.fingerprint.clone()),
                limit: 15,
                ..Filter::default()
            })?;
            let used_by = vault.jobs_using_key(&key.fingerprint)?;
            Ok((key, used_by, events, vault.customers()?, vault.jobs()?))
        })
        .await?;
    let names = Names::new(&customers, &jobs);
    let page = state.page(&auth, key.label(), Nav::Keys);
    let base = format!("/keys/{}", key.fingerprint);
    Ok(views::layout(
        page,
        html! {
            p.crumbs {
                a href={ "/customers/" (key.customer_id) } { (key.customer_name) } " / keys /"
            }
            h1 { (key.label()) " " (views::key_status(&key)) }
            dl.details {
                dt { "Fingerprint" } dd { (views::fingerprint(&key.fingerprint)) }
                dt { "User IDs" } dd { @for uid in &key.user_ids { div { (uid) } } }
                dt { "Algorithm" } dd { (key.algorithm) }
                dt { "Capabilities" } dd { (views::key_capabilities(&key)) }
                dt { "Created" } dd { (views::timestamp(key.created_at)) }
                dt { "Expires" } dd { @match key.expires_at { Some(at) => (views::timestamp(at)), None => "never" } }
                dt { "Added" } dd { (views::timestamp(key.added_at)) }
                dt { "Used by jobs" } dd {
                    @if used_by.is_empty() { span.muted { "none" } } @else { (used_by.join(", ")) }
                }
            }

            div.columns {
                section.card {
                    h2 { "Public key" }
                    p { "Share this with partners so they can encrypt to us or check our signatures." }
                    // A download, not a page: keep htmx out of it.
                    form method="post" action={ (base) "/public" } hx-boost="false" {
                        (views::csrf_field(&auth.csrf))
                        button type="submit" { "Download public key (.asc)" }
                    }
                }
                @if key.has_secret {
                    section.card {
                        h2 { "Export secret key" }
                        p { "The export is protected with a new passphrase. Exports are audited." }
                        form.stack method="post" action={ (base) "/secret" } hx-boost="false" {
                            (views::csrf_field(&auth.csrf))
                            label { "New passphrase" input type="password" name="passphrase" required minlength=(MIN_EXPORT_PASSPHRASE_LEN) autocomplete="new-password"; }
                            label { "Repeat passphrase" input type="password" name="repeat" required minlength=(MIN_EXPORT_PASSPHRASE_LEN) autocomplete="new-password"; }
                            button type="submit" { "Download secret key (.asc)" }
                        }
                    }
                }
            }

            section {
                h2 { "Recent activity" }
                (views::audit_table(&events, &names))
            }

            section.card.danger {
                h2 { "Delete key" }
                @if used_by.is_empty() {
                    p { "Deleted keys stay in the database so the audit log keeps resolving, but can no longer be used." }
                    form.inline method="post" action={ (base) "/delete" } {
                        (views::csrf_field(&auth.csrf))
                        (views::confirm_box("Delete this key"))
                        button.danger type="submit" { "Delete" }
                    }
                } @else {
                    p { "This key is used by " (used_by.join(", ")) ". Change or delete those jobs first." }
                }
            }
        },
    ))
}

#[derive(Deserialize)]
pub struct GenerateForm {
    user_id: String,
    algorithm: String,
}

pub async fn generate(
    State(state): State<AppState>,
    Path(customer_id): Path<i64>,
    posted: Posted<GenerateForm>,
) -> Redirect {
    let back = format!("/customers/{customer_id}");
    let outcome = async {
        let algorithm = match posted.form.algorithm.as_str() {
            "curve25519" => Algorithm::Curve25519,
            "rsa4096" => Algorithm::Rsa4096,
            other => {
                return Err(AppError::bad_request(format!(
                    "unknown algorithm {other:?}"
                )));
            }
        };
        let user_id = posted.form.user_id.trim().to_owned();
        if user_id.is_empty() {
            return Err(AppError::bad_request("the user ID must not be empty"));
        }
        // Make sure the customer exists before spending seconds on an RSA key.
        state
            .vault(move |vault| vault.customer_by_id(customer_id))
            .await?;
        // Generate outside the vault lock, which the job engine shares.
        let key = tokio::task::spawn_blocking(move || crypto::generate(&user_id, algorithm))
            .await
            .map_err(AppError::internal)??;
        let record = state
            .vault(move |vault| vault.add_generated_key(Actor::Admin, customer_id, key))
            .await?;
        Ok(format!(
            "Generated key {} ({}).",
            record.label(),
            views::key_id(&record.fingerprint)
        ))
    }
    .await;
    state.done(&posted.auth, &back, outcome)
}

pub async fn import(
    State(state): State<AppState>,
    auth: Authed,
    Path(customer_id): Path<i64>,
    multipart: Multipart,
) -> Response {
    let back = format!("/customers/{customer_id}");
    let outcome = import_upload(&state, &auth, customer_id, multipart).await;
    if let Err(e) = &outcome
        && e.status == axum::http::StatusCode::FORBIDDEN
    {
        // Failed CSRF check: don't act on the request at all.
        return AppError::new(e.status, e.message()).into_response();
    }
    state.done(&auth, &back, outcome).into_response()
}

async fn import_upload(
    state: &AppState,
    auth: &Authed,
    customer_id: i64,
    mut multipart: Multipart,
) -> Result<String, AppError> {
    let mut csrf = String::new();
    let mut data = Vec::new();
    let mut pasted = String::new();
    let mut passphrase = Zeroizing::new(String::new());
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(format!("upload failed: {e}")))?
    {
        let name = field.name().unwrap_or("").to_owned();
        let bad = |e: axum::extract::multipart::MultipartError| {
            AppError::bad_request(format!("upload failed: {e}"))
        };
        match name.as_str() {
            CSRF_FIELD => csrf = field.text().await.map_err(bad)?,
            "file" => data = field.bytes().await.map_err(bad)?.to_vec(),
            "armored" => pasted = field.text().await.map_err(bad)?,
            "passphrase" => *passphrase = field.text().await.map_err(bad)?,
            _ => {}
        }
    }
    auth.check_csrf(&csrf)?;
    if data.is_empty() {
        data = pasted.trim().as_bytes().to_vec();
    }
    if data.is_empty() {
        return Err(AppError::bad_request("choose a key file or paste a key"));
    }
    let imported = state
        .vault(move |vault| {
            let passphrase = Some(passphrase.as_str()).filter(|p| !p.is_empty());
            vault.import_keys(Actor::Admin, customer_id, &data, passphrase)
        })
        .await?;
    let summary: Vec<String> = imported
        .iter()
        .map(|key| {
            format!(
                "{} ({}{})",
                key.label(),
                views::key_id(&key.fingerprint),
                if key.has_secret { ", secret" } else { "" }
            )
        })
        .collect();
    Ok(format!("Imported {}.", summary.join(", ")))
}

pub async fn export_public(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
    posted: Posted<Empty>,
) -> Response {
    let result = state
        .vault(move |vault| {
            let key = vault.find_key(&fpr)?;
            Ok((vault.export_public(Actor::Admin, &key.fingerprint)?, key))
        })
        .await;
    match result {
        Ok((armored, key)) => download(&key, "public", armored),
        Err(e) => state.done(&posted.auth, "/keys", Err(e)).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ExportSecretForm {
    passphrase: String,
    repeat: String,
}

pub async fn export_secret(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
    posted: Posted<ExportSecretForm>,
) -> Response {
    let back = key_url(&fpr);
    let passphrase = Zeroizing::new(posted.form.passphrase);
    let repeat = Zeroizing::new(posted.form.repeat);
    if passphrase.chars().count() < MIN_EXPORT_PASSPHRASE_LEN {
        let e = AppError::bad_request(format!(
            "the passphrase must be at least {MIN_EXPORT_PASSPHRASE_LEN} characters"
        ));
        return state.done(&posted.auth, &back, Err(e)).into_response();
    }
    if *passphrase != *repeat {
        let e = AppError::bad_request("the two passphrases do not match");
        return state.done(&posted.auth, &back, Err(e)).into_response();
    }
    let result = state
        .vault(move |vault| {
            let key = vault.find_key(&fpr)?;
            Ok((
                vault.export_secret(Actor::Admin, &key.fingerprint, &passphrase)?,
                key,
            ))
        })
        .await;
    match result {
        Ok((armored, key)) => download(&key, "secret", armored),
        Err(e) => state.done(&posted.auth, &back, Err(e)).into_response(),
    }
}

/// The key's page, if `fpr` looks like a fingerprint. Path values are user input and end up
/// in a `Location` header.
fn key_url(fpr: &str) -> String {
    if !fpr.is_empty() && fpr.bytes().all(|b| b.is_ascii_hexdigit()) {
        format!("/keys/{fpr}")
    } else {
        "/keys".to_owned()
    }
}

fn download(key: &KeyRecord, kind: &str, armored: String) -> Response {
    let customer: String = key
        .customer_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let file_name = format!("{customer}-{}-{kind}.asc", views::key_id(&key.fingerprint));
    (
        [
            (header::CONTENT_TYPE, "application/pgp-keys".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file_name}\""),
            ),
        ],
        armored,
    )
        .into_response()
}

pub async fn delete(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
    posted: Posted<Confirmed>,
) -> Redirect {
    let back = key_url(&fpr);
    if let Err(e) = posted.form.check() {
        return state.done(&posted.auth, &back, Err(e));
    }
    match state
        .vault(move |vault| vault.delete_key(Actor::Admin, &fpr))
        .await
    {
        Ok(key) => state.done(
            &posted.auth,
            &format!("/customers/{}", key.customer_id),
            Ok(format!("Deleted key {}.", key.label())),
        ),
        Err(e) => state.done(&posted.auth, &back, Err(e)),
    }
}
